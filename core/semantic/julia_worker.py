import argparse
import json
import math
from pathlib import Path
import sys
import traceback


LABELS = [
    "not_likely_false_positive",
    "likely_false_positive",
    "uncertain",
]

def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--model", required=True)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--max-length", type=int, default=8192)
    parser.add_argument("--head-length", type=int, default=512)
    parser.add_argument("--fp-threshold", type=float, default=0.80)
    parser.add_argument("--decision-threshold", type=float, default=0.50)
    return parser.parse_args()


def emit(payload):
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def limited(value, maximum):
    text = str(value or "")
    if len(text) <= maximum:
        return text
    return text[:maximum]


def source_hint(value):
    normalized = str(value or "").replace("\\", "/").rstrip("/")
    parts = [part for part in normalized.split("/") if part]
    return "/".join(parts[-3:])


def detector_name(candidate):
    detector_type = limited(candidate.get("detector_type"), 256).strip()
    description = limited(candidate.get("description"), 512).strip()
    if description and detector_type:
        return f"{description} ({detector_type})"
    return description or detector_type or "the detected secret type"


def task_for(candidate):
    if str(candidate.get("category") or "").strip().lower() == "pii":
        return "pii"
    return "secret"


def detector_type_for(candidate):
    return str(candidate.get("detector_type") or "").strip().lower()


def inference_group_for(candidate):
    if detector_type_for(candidate) == "person_name":
        return "person_name"
    return task_for(candidate)


def question_for(candidate, rules_first=False):
    if not rules_first:
        if detector_type_for(candidate) == "person_name":
            return "Classify the semantic role of this person_name candidate."
        if task_for(candidate) == "pii":
            return (
                f"Which description matches this candidate detected as PII type {detector_name(candidate)}? "
                "Judge its semantic role, not whether it belongs to a known person."
            )
        return (
            f"Which description matches this candidate detected as {detector_name(candidate)}? "
            "Judge its semantic role, not whether the credential works."
        )

    if detector_type_for(candidate) == "person_name":
        return (
            "Does this exact value represent a person's name? Choose likely false positive only when the value or nearby "
            "context clearly shows a role, group, product, command, placeholder, mock, or other non-person label."
        )
    if task_for(candidate) == "pii":
        return (
            f"Is this exact value semantically compatible with PII type {detector_name(candidate)}? "
            "Do not verify who it belongs to. Choose likely false positive only when the value, source, or nearby context "
            "clearly proves that it is a placeholder, mock, unrelated fragment, or incompatible data type."
        )
    return (
        f"Is this exact value semantically compatible with credential type {detector_name(candidate)}? "
        "Do not test whether it works. Choose likely false positive only when the value, source, or nearby context clearly "
        "proves that it is an example, placeholder, mock, unrelated fragment, or incompatible data type."
    )


def options_for(candidate, rules_first=False):
    if not rules_first:
        if detector_type_for(candidate) == "person_name":
            return [
                "Personal name of an individual. Keep it.",
                "Non-person label, role, group, product, title, command, placeholder, or mock. Likely false positive.",
            ]
        if task_for(candidate) == "pii":
            return [
                "A value of the detected PII type. Keep it.",
                "Unrelated text, an incompatible fragment, or an obvious placeholder or mock. Likely false positive.",
            ]
        return [
            "A value of the detected credential type, whether active or inactive. Keep it.",
            "Unrelated harmless text, a placeholder, mock, path, domain, command, identifier, or fragment. Likely false positive.",
        ]

    if detector_type_for(candidate) == "person_name":
        return [
            "Keep: it can be a person's name and there is no clear false-positive evidence.",
            "Likely false positive: clear evidence shows a non-person label, placeholder, or mock.",
        ]
    if task_for(candidate) == "pii":
        return [
            "Keep: it is compatible with the detected PII type and there is no clear false-positive evidence.",
            "Likely false positive: clear evidence shows a placeholder, mock, unrelated fragment, or incompatible value.",
        ]
    return [
        "Keep: it is compatible with the detected credential type and there is no clear false-positive evidence.",
        "Likely false positive: clear evidence shows an example, placeholder, mock, unrelated fragment, or incompatible value.",
    ]


def candidate_state(candidate):
    tag = "pii_candidate" if task_for(candidate) == "pii" else "secret_candidate"
    lines = [
        f"<{tag}>",
        "detector_type: " + limited(candidate.get("detector_type"), 256),
    ]
    if task_for(candidate) == "pii":
        lines.append("category: pii")
    lines.extend(
        [
            "source_hint: " + limited(source_hint(candidate.get("source")), 1024),
            "line: " + str(candidate.get("line") or 0),
            "heuristic_confidence: " + str(candidate.get("heuristic_confidence") or 0),
            "description: " + limited(candidate.get("description"), 512),
            "value: " + limited(candidate.get("value"), 2048),
            "context:",
            limited(candidate.get("context"), 4096),
            f"</{tag}>",
        ]
    )
    return "\n".join(lines)


def numeric_probabilities(raw):
    if isinstance(raw, dict):
        values = [raw.get(str(index), 0.0) for index in range(len(LABELS))]
    elif isinstance(raw, list):
        values = raw
    else:
        values = []

    probabilities = []
    for value in values[: len(LABELS)]:
        try:
            number = float(value)
        except (TypeError, ValueError):
            number = 0.0
        probabilities.append(number if math.isfinite(number) else 0.0)
    while len(probabilities) < len(LABELS):
        probabilities.append(0.0)
    return probabilities


def softmax(values):
    if not values:
        return []
    finite = []
    for value in values:
        number = float(value)
        if not math.isfinite(number):
            raise FloatingPointError("Julia returned nonfinite logits")
        finite.append(number)
    maximum = max(finite)
    exponentials = [math.exp(value - maximum) for value in finite]
    total = sum(exponentials)
    return [value / total for value in exponentials]


def infer(engine, rows):
    if hasattr(engine, "logits"):
        return [
            {
                "index": max(range(len(values)), key=values.__getitem__),
                "probabilities": softmax(values),
            }
            for values in engine.logits(rows)
        ]
    return engine.predict(rows)


class Julia2Engine:
    def __init__(self, runtime):
        self.runtime = runtime

    def predict(self, rows):
        requests = []
        for row in rows:
            criteria = {str(index): option for index, option in enumerate(row["options"])}
            requests.append(
                {
                    "state": row["state"],
                    "questions": {
                        "verdict": {
                            "type": "choice",
                            "instructions": row["question"],
                            "criteria": criteria,
                        }
                    },
                }
            )

        predictions = self.runtime.predict_batch(requests)
        results = []
        for prediction in predictions:
            answer = prediction["answers"]["verdict"]
            probabilities = answer.get("probabilities", {})
            values = [float(probabilities.get(str(index), 0.0)) for index in range(len(LABELS))]
            choice = str(answer.get("choice", "2"))
            index = int(choice) if choice.isdigit() else 2
            results.append({"index": index, "probabilities": values})
        return results


def load_engine(args):
    model_root = Path(args.model).resolve()
    bundled_runtime = model_root / "runtime"
    if (bundled_runtime / "julia2" / "__init__.py").is_file():
        sys.path.insert(0, str(bundled_runtime))
        from julia2 import Runtime

        runtime = Runtime(str(model_root), device=args.device, max_len=args.max_length, modalities=("text",))
        return Julia2Engine(runtime), "julia-2"

    if (bundled_runtime / "julia15" / "__init__.py").is_file():
        sys.path.insert(0, str(bundled_runtime))
        from julia15 import Runtime

        return Runtime(str(model_root), device=args.device, strict=True), "julia-1.5"

    sys.path.insert(0, str(model_root))
    from julia import load_model

    return (
        load_model(
            str(model_root),
            device=args.device,
            strict_encoding=True,
            max_length=args.max_length,
            head_length=args.head_length,
        ),
        "julia-1",
    )


def classify(engine, candidates, fp_threshold, decision_threshold, model_family):
    raw_results = [None] * len(candidates)
    groups = {}
    for index, candidate in enumerate(candidates):
        groups.setdefault(inference_group_for(candidate), []).append(index)

    for indexes in groups.values():
        rows = [
            {
                "state": candidate_state(candidates[index]),
                "question": question_for(candidates[index], rules_first=model_family == "julia-2"),
                "options": options_for(candidates[index], rules_first=model_family == "julia-2"),
                "type": "choice",
            }
            for index in indexes
        ]
        group_results = infer(engine, rows)
        if len(group_results) != len(indexes):
            raise RuntimeError("Julia returned an unexpected number of predictions")
        for index, raw in zip(indexes, group_results):
            raw_results[index] = raw

    results = []

    for raw, candidate in zip(raw_results, candidates):
        index = int(raw.get("index", 2))
        if index < 0 or index >= len(LABELS):
            index = 2
        probabilities = numeric_probabilities(raw.get("probabilities"))
        top_score = probabilities[index]
        verdict = LABELS[index]

        if verdict == "likely_false_positive" and top_score < fp_threshold:
            verdict = "uncertain"
        elif verdict == "not_likely_false_positive" and top_score < decision_threshold:
            verdict = "uncertain"

        if task_for(candidate) == "pii" and verdict == "not_likely_false_positive":
            verdict = "uncertain"

        results.append(
            {
                "verdict": verdict,
                "score": top_score,
                "probabilities": dict(zip(LABELS, probabilities)),
            }
        )
    return results


def main():
    args = parse_args()

    try:
        engine, model_family = load_engine(args)
    except Exception as exc:
        emit({"type": "startup_error", "error": f"{type(exc).__name__}: {exc}"})
        return 1

    emit({"type": "ready", "model_family": model_family})

    for line in sys.stdin:
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            emit({"type": "error", "error": "invalid JSON request"})
            continue

        request_type = request.get("type")
        if request_type == "shutdown":
            emit({"type": "stopped"})
            return 0
        if request_type != "classify":
            emit({"type": "error", "id": request.get("id"), "error": "unsupported request type"})
            continue

        try:
            results = classify(
                engine,
                request.get("candidates") or [],
                args.fp_threshold,
                args.decision_threshold,
                model_family,
            )
            emit({"type": "result", "id": request.get("id"), "results": results})
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            emit(
                {
                    "type": "error",
                    "id": request.get("id"),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
