import argparse
import collections
import json
import math
import pathlib
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"
CORPUS = ROOT / "corpus"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path, default=MANIFEST)
    parser.add_argument("--corpus", type=pathlib.Path, default=CORPUS)
    parser.add_argument("--include-categories")
    parser.add_argument("--model", type=pathlib.Path)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--fp-threshold", type=float, default=0.80)
    parser.add_argument("--detector-only", action="store_true")
    parser.add_argument("--skip-suppression-check", action="store_true")
    parser.add_argument("--strict-semantic-labels", action="store_true")
    parser.add_argument("--min-suppression-recall", type=float, default=0.25)
    return parser.parse_args()


def shannon_entropy(value):
    if not value:
        return 0.0
    counts = collections.Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def normalized_source(source):
    normalized = str(source).replace("\\", "/")
    marker = "/deployment/"
    if marker in normalized:
        return normalized.split(marker, 1)[1]
    return normalized.rsplit("/", 1)[-1]


def run_scan(args, scan_root, output_path, suppress):
    command = [
        str(args.binary.resolve()),
        str(scan_root),
        "--no-progress",
        "--silent",
        "--output",
        str(output_path),
    ]
    if args.include_categories:
        command.extend(["--include-categories", args.include_categories])
    if not args.detector_only:
        command.extend(
            [
                "--semantic-filter",
                "--semantic-model",
                str(args.model.resolve()),
                "--semantic-python",
                args.python,
                "--semantic-device",
                args.device,
                "--semantic-fp-threshold",
                str(args.fp_threshold),
            ]
        )
        if suppress:
            command.append("--suppress-likely-false-positives")

    completed = subprocess.run(command, text=True, capture_output=True)
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)
    return json.loads(output_path.read_text(encoding="utf-8"))


def index_findings(findings):
    indexed = collections.defaultdict(list)
    for finding in findings:
        key = (normalized_source(finding.get("source_url", "")), int(finding.get("line") or 0))
        indexed[key].append(finding)
    return indexed


def candidate_identity(finding):
    return (
        normalized_source(finding.get("source_url", "")),
        int(finding.get("line") or 0),
        finding.get("type"),
        finding.get("value"),
    )


def occurrence_identity(finding):
    return candidate_identity(finding) + (int(finding.get("byte_offset") or 0),)


def expected_types(case):
    single = case.get("expected_type")
    if single:
        return {single}
    return set()


def evaluate_manifest(manifest, findings, detector_only):
    indexed = index_findings(findings)
    failures = []
    semantic_total = 0
    semantic_correct = 0
    semantic_mismatches = []
    expected_locations = set()
    expected_candidates = collections.defaultdict(set)

    for case in manifest["cases"]:
        key = (case["file"], case["line"])
        expected_locations.add(key)
        location_findings = indexed.get(key, [])
        same_value = [finding for finding in location_findings if finding.get("value") == case["value"]]
        expects_semantic = case["expected_stage"] == "semantic"
        types = expected_types(case)
        if expects_semantic:
            if not types:
                failures.append(f'{case["id"]}: semantic case has no expected_type')
            for expected_type in types:
                expected_candidates[key].add((expected_type, case["value"]))
        matched = [finding for finding in same_value if not types or finding.get("type") in types]

        if expects_semantic and not matched:
            if same_value:
                actual_types = sorted({finding.get("type") for finding in same_value})
                failures.append(
                    f'{case["id"]}: expected type {sorted(types)}, got {actual_types}'
                )
            else:
                failures.append(f'{case["id"]}: expected detector output, but no finding reached the semantic stage')
            continue
        if not expects_semantic and same_value:
            failures.append(f'{case["id"]}: expected heuristic rejection, but {len(same_value)} finding(s) were emitted')
            continue

        if expects_semantic:
            expected_count = int(case.get("expected_count", 1))
            actual_count = sum(int(finding.get("occurrences") or 1) for finding in matched)
            if actual_count != expected_count:
                failures.append(
                    f'{case["id"]}: expected {expected_count} occurrence(s), got {actual_count}'
                )
        if detector_only or not expects_semantic:
            continue

        semantic_total += len(matched)
        expected_filter = case["expected_filter"]
        statuses = [finding.get("filter_status") for finding in matched]
        semantic_correct += sum(status == expected_filter for status in statuses)
        if any(status != expected_filter for status in statuses):
            semantic_mismatches.append(f'{case["id"]}: expected {expected_filter}, got {statuses}')

    unexpected = sorted(key for key in indexed if key not in expected_locations)
    if unexpected:
        failures.append(f"unexpected finding locations: {unexpected}")
    for key, location_findings in indexed.items():
        if key not in expected_locations:
            continue
        for finding in location_findings:
            candidate = (finding.get("type"), finding.get("value"))
            if candidate not in expected_candidates[key]:
                failures.append(
                    f"unexpected finding at {key}: type={finding.get('type')} value={finding.get('value')!r}"
                )

    return failures, semantic_mismatches, semantic_total, semantic_correct


def evaluate_suppression(manifest, marked, suppressed):
    suppressed_identities = {occurrence_identity(item) for item in suppressed}
    expected_by_candidate = {}
    for case in manifest["cases"]:
        if case["expected_stage"] != "semantic":
            continue
        for expected_type in expected_types(case):
            expected_by_candidate[(case["file"], case["line"], expected_type, case["value"])] = case[
                "expected_filter"
            ]
    failures = []
    model_suppressed = 0
    safe_suppressed = 0
    eligible_false_positives = 0

    for finding in marked:
        candidate = candidate_identity(finding)
        identity = occurrence_identity(finding)
        status = finding.get("filter_status")
        expected = expected_by_candidate.get(candidate)
        if expected == "likely_false_positive":
            eligible_false_positives += 1
        if status == "likely_false_positive":
            model_suppressed += 1
            if identity in suppressed_identities:
                failures.append(f"likely false positive was not suppressed: {identity[:3]}")
            if expected != "likely_false_positive":
                failures.append(f"unsafe suppression: {identity[:3]} expected={expected}")
            else:
                safe_suppressed += 1
        elif identity not in suppressed_identities:
            failures.append(f"non-false-positive finding was suppressed: {identity[:3]} status={status}")

    return failures, model_suppressed, safe_suppressed, eligible_false_positives


def main():
    args = parse_args()
    if not 0.0 <= args.min_suppression_recall <= 1.0:
        raise SystemExit("--min-suppression-recall must be between 0 and 1")
    if not args.binary.is_file():
        raise SystemExit(f"binary not found: {args.binary}")
    if not args.detector_only and (args.model is None or not args.model.is_dir()):
        raise SystemExit("--model must point to a local Julia-1 repository")

    if not args.manifest.is_file():
        raise SystemExit(f"manifest not found: {args.manifest}")
    if not args.corpus.is_dir():
        raise SystemExit(f"corpus not found: {args.corpus}")

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    entropy_groups = collections.Counter(case["entropy_gate"] for case in manifest["cases"])
    measured_entropy = [shannon_entropy(case["value"]) for case in manifest["cases"]]

    with tempfile.TemporaryDirectory(prefix="secrethound-semantic-") as temporary:
        deployment = pathlib.Path(temporary) / "deployment"
        shutil.copytree(args.corpus, deployment)
        marked = run_scan(args, deployment, pathlib.Path(temporary) / "marked.json", suppress=False)
        failures, semantic_mismatches, semantic_total, semantic_correct = evaluate_manifest(manifest, marked, args.detector_only)
        if args.strict_semantic_labels:
            failures.extend(semantic_mismatches)

        model_suppressed = 0
        safe_suppressed = 0
        eligible_false_positives = 0
        if not args.detector_only and not args.skip_suppression_check:
            suppressed = run_scan(args, deployment, pathlib.Path(temporary) / "suppressed.json", suppress=True)
            suppression_failures, model_suppressed, safe_suppressed, eligible_false_positives = evaluate_suppression(
                manifest, marked, suppressed
            )
            failures.extend(suppression_failures)

    print(f"cases={len(manifest['cases'])}")
    print(f"findings={len(marked)}")
    print(
        "entropy_cases="
        + ",".join(f"{name}:{count}" for name, count in sorted(entropy_groups.items()))
        + f" measured_min={min(measured_entropy):.3f} measured_max={max(measured_entropy):.3f}"
    )
    if not args.detector_only:
        accuracy = (semantic_correct / semantic_total) if semantic_total else 0.0
        print(f"semantic_predictions={semantic_total} correct={semantic_correct} accuracy={accuracy:.4f}")
        print(f"semantic_mismatches={len(semantic_mismatches)}")
        if not args.skip_suppression_check:
            precision = (safe_suppressed / model_suppressed) if model_suppressed else 1.0
            recall = (safe_suppressed / eligible_false_positives) if eligible_false_positives else 1.0
            if recall < args.min_suppression_recall:
                failures.append(
                    f"suppression recall {recall:.4f} is below required {args.min_suppression_recall:.4f}"
                )
            print(
                f"model_suppressed={model_suppressed} eligible_false_positives={eligible_false_positives} "
                f"suppression_precision={precision:.4f} suppression_recall={recall:.4f}"
            )

    if failures:
        print("failures:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    if not args.detector_only and semantic_mismatches and not args.strict_semantic_labels:
        print(
            "benchmark safety gates satisfied; "
            f"{len(semantic_mismatches)} semantic label mismatch(es) remain non-gating"
        )
    else:
        print("benchmark expectations satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
