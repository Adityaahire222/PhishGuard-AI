import csv
import json
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.evaluate_dataset import DatasetError, calculate_metrics, load_dataset
from scripts import evaluate_dataset


def test_running_api_metadata_is_captured_without_sensitive_content(monkeypatch):
    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {
                "status": "ok",
                "inference": {
                    "model_tag": "qwen2.5:3b",
                    "prompt_sha256": "a" * 64,
                    "generation_settings": {
                        "stream": False,
                        "options": {"temperature": 0},
                        "format": "json_schema",
                        "format_schema_sha256": "b" * 64,
                    },
                },
            }

    monkeypatch.setattr(evaluate_dataset.requests, "get", lambda *_args, **_kwargs: Response())
    metadata = evaluate_dataset._read_service_metadata("http://127.0.0.1:8000")
    assert metadata["inference_metadata_status"] == "available"
    assert metadata["model_tag"] == "qwen2.5:3b"
    assert metadata["prompt_sha256"] == "a" * 64
    assert metadata["generation_settings"]["options"] == {"temperature": 0}


@pytest.mark.parametrize("failure", [
    "connection",
    "malformed",
    "missing_metadata",
])
def test_service_metadata_failure_does_not_abort_evaluation(failure, monkeypatch):
    if failure == "connection":
        def unavailable(*_args, **_kwargs):
            raise evaluate_dataset.requests.ConnectionError()
        monkeypatch.setattr(evaluate_dataset.requests, "get", unavailable)
    else:
        class Response:
            status_code = 200

            @staticmethod
            def json():
                return {"status": "ok"} if failure == "missing_metadata" else ["unexpected"]

        monkeypatch.setattr(evaluate_dataset.requests, "get", lambda *_args, **_kwargs: Response())

    assert evaluate_dataset._read_service_metadata("http://127.0.0.1:8000") == {
        "inference_metadata_status": "unavailable"
    }


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        fields = ["email_text", "label"]
        if any("source_files" in row for row in rows):
            fields.append("source_files")
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_load_dataset_validates_labels_and_counts_duplicates():
    path = Path.cwd() / f"evaluation-test-{uuid4().hex}.csv"
    try:
        write_csv(path, [
            {"email_text": "first message", "label": "phishing"},
            {"email_text": "first message", "label": "PHISHING"},
        ])
        samples, info = load_dataset(path)
    finally:
        path.unlink(missing_ok=True)
    assert len(samples) == 2
    assert samples[0]["label"] == "PHISHING"
    assert samples[0]["source_files"] == '["UNKNOWN"]'
    assert info["duplicate_rows"] == 1


@pytest.mark.parametrize("source_value", ["", "not-json", "{}", "[]"])
def test_missing_or_unknown_source_identifiers_are_explicitly_unknown(source_value):
    path = Path.cwd() / f"evaluation-source-test-{uuid4().hex}.csv"
    try:
        write_csv(path, [{"email_text": "sample", "label": "PHISHING", "source_files": source_value}])
        samples, _ = load_dataset(path)
    finally:
        path.unlink(missing_ok=True)
    assert json.loads(samples[0]["source_files"]) == ["UNKNOWN"]


def test_source_identifiers_map_dataset_rows_to_prediction_rows(tmp_path, monkeypatch):
    dataset = tmp_path / "provenance.csv"
    write_csv(dataset, [{
        "email_text": "sample 7 email",
        "label": "PHISHING",
        "source_files": '["raw/message-000010.eml", "raw/message-copy.eml"]',
    }])
    samples, _ = load_dataset(dataset)

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {
                "classification": "SUSPICIOUS",
                "risk_level": "MEDIUM",
                "indicators": ["account update", "lookalike subject"],
                "explanation": "Model-generated explanation; not verified ground truth.",
                "recommended_action": "Verify via a trusted channel.",
            }

    class Session:
        def post(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(evaluate_dataset.requests, "Session", lambda: Session())
    predictions = evaluate_dataset.evaluate(samples, "http://127.0.0.1:8000", 1)
    assert predictions[0]["sample_id"] == 1
    assert json.loads(predictions[0]["source_files"]) == ["raw/message-000010.eml", "raw/message-copy.eml"]
    assert json.loads(predictions[0]["indicators"]) == ["account update", "lookalike subject"]
    assert predictions[0]["explanation"].startswith("Model-generated")
    assert predictions[0]["recommended_action"] == "Verify via a trusted channel."

    output = tmp_path / "reports"
    metrics = calculate_metrics(predictions)
    evaluate_dataset.write_reports(predictions, metrics, output, {})
    with (output / "predictions.csv").open(encoding="utf-8", newline="") as stream:
        report_rows = list(csv.DictReader(stream))
    assert report_rows[0]["sample_id"] == "1"
    assert json.loads(report_rows[0]["source_files"]) == ["raw/message-000010.eml", "raw/message-copy.eml"]
    assert json.loads(report_rows[0]["indicators"]) == ["account update", "lookalike subject"]
    assert report_rows[0]["explanation"].startswith("Model-generated")
    assert report_rows[0]["recommended_action"] == "Verify via a trusted channel."


@pytest.mark.parametrize("optional_fields", [
    {},
    {"indicators": "malformed", "explanation": 12, "recommended_action": None},
    {"indicators": ["valid", 3], "explanation": ["not text"]},
])
def test_missing_or_malformed_optional_response_fields_are_safe(optional_fields, tmp_path, monkeypatch):
    dataset = tmp_path / "sample.csv"
    write_csv(dataset, [{"email_text": "sample", "label": "PHISHING"}])
    samples, _ = load_dataset(dataset)

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"classification": "PHISHING", "risk_level": "HIGH", **optional_fields}

    class Session:
        def post(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(evaluate_dataset.requests, "Session", lambda: Session())
    prediction = evaluate_dataset.evaluate(samples, "http://localhost", 1)[0]
    assert prediction["status"] == "ok"
    assert prediction["indicators"] == "[]"
    assert prediction["explanation"] == ""
    assert prediction["recommended_action"] == ""


def test_api_failures_remain_failures_with_empty_diagnostics(tmp_path, monkeypatch):
    dataset = tmp_path / "sample.csv"
    write_csv(dataset, [{"email_text": "sample", "label": "PHISHING"}])
    samples, _ = load_dataset(dataset)

    class Response:
        status_code = 503

        @staticmethod
        def json():
            raise AssertionError("failure responses should not be parsed as predictions")

    class Session:
        def post(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(evaluate_dataset.requests, "Session", lambda: Session())
    prediction = evaluate_dataset.evaluate(samples, "http://localhost", 1)[0]
    assert prediction["status"] == "error"
    assert prediction["prediction"] is None
    assert prediction["indicators"] == "[]"
    assert prediction["explanation"] == ""
    assert calculate_metrics([prediction])["failed_count"] == 1


@pytest.mark.parametrize("rows", [
    [{"email_text": "", "label": "PHISHING"}],
    [{"email_text": "content", "label": ""}],
    [{"email_text": "content", "label": "SPAM"}],
])
def test_load_dataset_rejects_missing_or_unknown_values(rows):
    path = Path.cwd() / f"evaluation-test-{uuid4().hex}.csv"
    try:
        write_csv(path, rows)
        with pytest.raises(DatasetError):
            load_dataset(path)
    finally:
        path.unlink(missing_ok=True)


def test_metrics_confusion_fpr_abstention_and_latency():
    rows = [
        {"ground_truth": "PHISHING", "prediction": "PHISHING", "status": "ok", "latency_seconds": 1.0},
        {"ground_truth": "LEGITIMATE", "prediction": "PHISHING", "status": "ok", "latency_seconds": 3.0},
        {"ground_truth": "PHISHING", "prediction": "INCONCLUSIVE", "status": "ok", "latency_seconds": 2.0},
        {"ground_truth": "SUSPICIOUS", "prediction": None, "status": "error", "latency_seconds": 8.0},
    ]
    result = calculate_metrics(rows)
    assert result["confusion_matrix"]["PHISHING"]["PHISHING"] == 1
    assert result["false_positive_rate_phishing_positive"] == pytest.approx(1.0)
    assert result["abstention_rate"] == pytest.approx(1 / 3)
    assert result["failed_count"] == 1
    assert result["latency_seconds"]["mean"] == pytest.approx(2.0)
    assert result["per_class"]["PHISHING"]["recall"] == pytest.approx(0.5)

