import argparse
import json
import math
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
    parser.add_argument("--decision-threshold", type=float, default=0.60)
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


def question_for(candidate):
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


def options_for(candidate):
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


def classify(engine, candidates, fp_threshold, decision_threshold):
    raw_results = [None] * len(candidates)
    groups = {}
    for index, candidate in enumerate(candidates):
        groups.setdefault(inference_group_for(candidate), []).append(index)

    for indexes in groups.values():
        rows = [
            {
                "state": candidate_state(candidates[index]),
                "question": question_for(candidates[index]),
                "options": options_for(candidates[index]),
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
    sys.path.insert(0, args.model)

    try:
        from julia import load_model

        engine = load_model(
            args.model,
            device=args.device,
            strict_encoding=True,
            max_length=args.max_length,
            head_length=args.head_length,
        )
    except Exception as exc:
        emit({"type": "startup_error", "error": f"{type(exc).__name__}: {exc}"})
        return 1

    emit({"type": "ready"})

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
