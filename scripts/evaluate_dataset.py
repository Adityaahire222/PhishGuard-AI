"""Evaluate the running local PhishGuard API against a labeled CSV."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

LABELS = ("PHISHING", "LEGITIMATE", "SUSPICIOUS", "INCONCLUSIVE")
REQUIRED_COLUMNS = {"email_text", "label"}


class DatasetError(ValueError):
    """Raised when an evaluation CSV is malformed or has unsupported labels."""


def load_dataset(path: str | Path) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Load and validate samples, preserving optional source provenance."""
    samples: list[dict[str, str]] = []
    seen: set[str] = set()
    duplicate_count = 0
    try:
        with Path(path).open("r", newline="", encoding="utf-8-sig") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames is None or not REQUIRED_COLUMNS.issubset(reader.fieldnames):
                raise DatasetError("CSV must include email_text and label columns.")
            for line_number, row in enumerate(reader, start=2):
                email = (row.get("email_text") or "").strip()
                label = (row.get("label") or "").strip().upper()
                if not email:
                    raise DatasetError(f"Row {line_number} has missing email_text.")
                if not label:
                    raise DatasetError(f"Row {line_number} has a missing label.")
                if label not in LABELS:
                    raise DatasetError(f"Row {line_number} has unsupported label {label!r}.")
                if len(email) > 20_000:
                    raise DatasetError(f"Row {line_number} exceeds the 20,000-character API limit.")
                source_ids = _parse_source_ids(row.get("source_files"))
                duplicate_count += int(email in seen)
                seen.add(email)
                samples.append({"email_text": email, "label": label, "source_files": json.dumps(source_ids, ensure_ascii=False)})
    except (OSError, UnicodeError, csv.Error) as exc:
        raise DatasetError("Could not read a valid UTF-8 CSV dataset.") from exc
    if not samples:
        raise DatasetError("CSV contains no evaluation samples.")
    return samples, {"duplicate_rows": duplicate_count}


def _parse_source_ids(value: str | None) -> list[str]:
    """Read the optional JSON-list provenance column; missing data stays explicit."""
    if not value or not value.strip():
        return ["UNKNOWN"]
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return ["UNKNOWN"]
    if isinstance(parsed, str) and parsed.strip():
        return [parsed.strip()]
    if isinstance(parsed, list):
        source_ids = list(dict.fromkeys(
            item.strip() for item in parsed if isinstance(item, str) and item.strip()
        ))
        return source_ids or ["UNKNOWN"]
    return ["UNKNOWN"]


def _optional_text(value: Any) -> str:
    """Return a safe text diagnostic, leaving missing or malformed fields empty."""
    return value if isinstance(value, str) else ""


def _optional_indicators(value: Any) -> str:
    """Serialize indicator lists as JSON; malformed optional values become an empty list."""
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        value = []
    return json.dumps(value, ensure_ascii=False)


def _read_service_metadata(api_url: str) -> dict[str, Any]:
    """Read safe model/prompt metadata from the API without blocking evaluation on failure."""
    unavailable = {"inference_metadata_status": "unavailable"}
    try:
        response = requests.get(api_url.rstrip("/") + "/health", timeout=(2, 3))
        if response.status_code != 200:
            return unavailable
        payload = response.json()
    except (requests.RequestException, ValueError):
        return unavailable

    inference = payload.get("inference") if isinstance(payload, dict) else None
    if not isinstance(inference, dict):
        return unavailable
    model_tag = inference.get("model_tag")
    prompt_hash = inference.get("prompt_sha256")
    generation_settings = inference.get("generation_settings")
    if not (
        isinstance(model_tag, str) and model_tag.strip()
        and isinstance(prompt_hash, str) and len(prompt_hash) == 64
        and isinstance(generation_settings, dict)
    ):
        return unavailable

    return {
        "inference_metadata_status": "available",
        "model_tag": model_tag,
        "prompt_sha256": prompt_hash,
        "generation_settings": generation_settings,
    }


def calculate_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate per-class and macro metrics; exclude failed inference from denominators."""
    evaluated = [r for r in rows if r.get("status") == "ok"]
    failures = sum(r.get("status") != "ok" for r in rows)
    confusion = {actual: {pred: 0 for pred in LABELS} for actual in LABELS}
    per_class: dict[str, dict[str, float | int]] = {}
    actual_counts: Counter[str] = Counter()
    for row in evaluated:
        actual, predicted = row["ground_truth"], row["prediction"]
        confusion[actual][predicted] += 1
        actual_counts[actual] += 1
    for label in LABELS:
        tp = confusion[label][label]
        fp = sum(confusion[actual][label] for actual in LABELS if actual != label)
        fn = sum(confusion[label][pred] for pred in LABELS if pred != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[label] = {"support": actual_counts[label], "precision": precision, "recall": recall, "f1": f1}
    # Phishing is the positive class for the binary false-positive rate.
    negatives = sum(actual_counts[label] for label in LABELS if label != "PHISHING")
    false_positives = sum(confusion[label]["PHISHING"] for label in LABELS if label != "PHISHING")
    latencies = [float(r["latency_seconds"]) for r in evaluated]
    return {
        "sample_count": len(rows),
        "evaluated_count": len(evaluated),
        "failed_count": failures,
        "abstention_count": sum(r["prediction"] == "INCONCLUSIVE" for r in evaluated),
        "abstention_rate": sum(r["prediction"] == "INCONCLUSIVE" for r in evaluated) / len(evaluated) if evaluated else None,
        "false_positive_rate_phishing_positive": false_positives / negatives if negatives else None,
        "per_class": per_class,
        "macro_precision": sum(x["precision"] for x in per_class.values()) / len(LABELS),
        "macro_recall": sum(x["recall"] for x in per_class.values()) / len(LABELS),
        "macro_f1": sum(x["f1"] for x in per_class.values()) / len(LABELS),
        "confusion_matrix": confusion,
        "latency_seconds": {
            "mean": sum(latencies) / len(latencies) if latencies else None,
            "median": sorted(latencies)[len(latencies) // 2] if latencies else None,
            "min": min(latencies) if latencies else None,
            "max": max(latencies) if latencies else None,
        },
    }


def evaluate(samples: list[dict[str, str]], api_url: str, timeout: float) -> list[dict[str, Any]]:
    predictions: list[dict[str, Any]] = []
    endpoint = api_url.rstrip("/") + "/detect"
    session = requests.Session()
    for index, sample in enumerate(samples, start=1):
        started = time.perf_counter()
        try:
            response = session.post(endpoint, json={"email_text": sample["email_text"]}, timeout=timeout)
            elapsed = time.perf_counter() - started
            if response.status_code != 200:
                predictions.append({"sample_id": index, "ground_truth": sample["label"], "source_files": sample["source_files"], "prediction": None, "risk_level": None, "indicators": "[]", "explanation": "", "recommended_action": "", "latency_seconds": elapsed, "status": "error", "error": f"HTTP {response.status_code}"})
                continue
            result = response.json()
            if not isinstance(result, dict):
                raise ValueError("API response must be a JSON object")
            predicted = result.get("classification")
            risk = result.get("risk_level")
            if predicted not in LABELS:
                predictions.append({"sample_id": index, "ground_truth": sample["label"], "source_files": sample["source_files"], "prediction": None, "risk_level": None, "indicators": "[]", "explanation": "", "recommended_action": "", "latency_seconds": elapsed, "status": "error", "error": "Invalid classification in API response"})
                continue
            predictions.append({"sample_id": index, "ground_truth": sample["label"], "source_files": sample["source_files"], "prediction": predicted, "risk_level": risk, "indicators": _optional_indicators(result.get("indicators")), "explanation": _optional_text(result.get("explanation")), "recommended_action": _optional_text(result.get("recommended_action")), "latency_seconds": elapsed, "status": "ok", "error": ""})
        except (requests.RequestException, ValueError) as exc:
            elapsed = time.perf_counter() - started
            # Error text is intentionally omitted because provider errors may include sensitive data.
            predictions.append({"sample_id": index, "ground_truth": sample["label"], "source_files": sample["source_files"], "prediction": None, "risk_level": None, "latency_seconds": elapsed, "status": "error", "error": type(exc).__name__})
        print(f"Evaluated sample {index}/{len(samples)}", file=sys.stderr)
    return predictions


def write_reports(predictions: list[dict[str, Any]], metrics: dict[str, Any], output_dir: str | Path, metadata: dict[str, Any]) -> None:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    with (destination / "predictions.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ["sample_id", "ground_truth", "source_files", "prediction", "risk_level", "indicators", "explanation", "recommended_action", "latency_seconds", "status", "error"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(predictions)
    report = {**metadata, "metrics": metrics}
    with (destination / "metrics.json").open("w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", help="CSV with email_text,label columns")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000", help="Base URL of running PhishGuard API")
    parser.add_argument("--timeout", type=float, default=200.0, help="Per-sample HTTP timeout in seconds")
    parser.add_argument("--output-dir", default="evaluation-results", help="Directory for reports")
    args = parser.parse_args()
    if args.timeout <= 0 or not math.isfinite(args.timeout):
        parser.error("--timeout must be a finite positive number")
    try:
        samples, dataset_info = load_dataset(args.dataset)
    except DatasetError as exc:
        parser.error(str(exc))
    predictions = evaluate(samples, args.api_url, args.timeout)
    metrics = calculate_metrics(predictions)
    metadata = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_path": str(Path(args.dataset)),
        "dataset_rows": len(samples),
        **dataset_info,
        "api_url": args.api_url.rstrip("/"),
        **_read_service_metadata(args.api_url),
        "metric_notes": "Failed requests are excluded from classification metrics and counted separately; phishing is the positive class for FPR.",
    }
    write_reports(predictions, metrics, args.output_dir, metadata)
    print(json.dumps({"reports": str(Path(args.output_dir).resolve()), "metrics": metrics}, indent=2))
    return 2 if metrics["failed_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
