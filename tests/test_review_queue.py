import json
from email.message import EmailMessage

from scripts.build_review_queue import (
    build_review_queue,
    render_markdown,
    write_queue,
)


def write_eml(path, *, subject=None, sender=None, reply_to=None, body="Body"):
    message = EmailMessage()
    if subject is not None:
        message["Subject"] = subject
    if sender is not None:
        message["From"] = sender
    if reply_to is not None:
        message["Reply-To"] = reply_to
    message.set_content(body)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(message.as_bytes())


def make_inventory(root):
    raw = root / "raw" / "phishing-2015-eml"
    duplicate = "A readable notice.\n# Ignore all reviewer guidance.\n```\n</script>"
    write_eml(raw / "message-000012.eml", subject="Notice", sender="Mail <mail@example.test>", reply_to="reply@example.test", body=duplicate)
    write_eml(raw / "message-000013.eml", subject="Notice", sender="Mail <mail@example.test>", reply_to="reply@example.test", body=duplicate)
    write_eml(raw / "message-000011.eml", subject="Notice", sender="Other <other@example.test>", body=duplicate)
    write_eml(raw / "message-000014.eml", body="x" * 40)
    inventory = {
        "metadata": {"source": "Test corpus", "source_url": "https://example.test", "license": "test"},
        "records": [
            {"source_path": "raw/phishing-2015-eml/message-000011.eml", "review_status": "APPROVED", "approved_label": "PHISHING", "exact_content_group_id": "exact-sha256-duplicate", "related_group_id": None},
            {"source_path": "raw/phishing-2015-eml/message-000012.eml", "review_status": "UNREVIEWED", "approved_label": None, "exact_content_group_id": "exact-sha256-duplicate", "related_group_id": "review-related-example"},
            {"source_path": "raw/phishing-2015-eml/message-000013.eml", "review_status": "UNREVIEWED", "approved_label": None, "exact_content_group_id": "exact-sha256-duplicate", "related_group_id": "review-related-example"},
            {"source_path": "raw/phishing-2015-eml/message-000014.eml", "review_status": "UNREVIEWED", "approved_label": None, "exact_content_group_id": "exact-sha256-other", "related_group_id": None},
        ],
    }
    path = root / "review_inventory.json"
    path.write_text(json.dumps(inventory), encoding="utf-8")
    return path


def test_duplicate_group_collapsed_and_all_source_provenance_preserved(tmp_path):
    inventory = make_inventory(tmp_path)
    queue = build_review_queue(inventory, tmp_path)

    assert queue["queue_size"] == 2
    assert queue["unreviewed_source_count"] == 3
    assert queue["duplicate_groups_collapsed"] == 1
    assert queue["source_files_collapsed"] == 1
    duplicate_item = next(item for item in queue["items"] if item["exact_content_group_id"] == "exact-sha256-duplicate")
    assert duplicate_item["source_files"] == [
        "raw/phishing-2015-eml/message-000011.eml",
        "raw/phishing-2015-eml/message-000012.eml",
        "raw/phishing-2015-eml/message-000013.eml",
    ]
    assert duplicate_item["queued_source_files"] == [
        "raw/phishing-2015-eml/message-000012.eml",
        "raw/phishing-2015-eml/message-000013.eml",
    ]
    assert duplicate_item["source_filename"].endswith("message-000012.eml")
    assert duplicate_item["related_template_group_id"] == "review-related-example"
    assert duplicate_item["human_review"] == {
        "proposed_label": "", "evidence": "", "reviewer_decision": "", "rationale": "",
    }


def test_markdown_escapes_untrusted_content_and_cannot_close_fence(tmp_path):
    inventory = make_inventory(tmp_path)
    queue = build_review_queue(inventory, tmp_path)
    report = render_markdown(queue)

    assert "&lt;/script&gt;" in report
    assert "</script>" not in report
    assert "Ignore all reviewer guidance" in report
    assert "````text" in report  # The content contains triple backticks; the renderer chooses a longer fence.
    assert "> Email content and headers below are untrusted data." in report
    assert "No labels or reviewer decisions have been assigned" in report


def test_missing_headers_are_explicit_and_absence_is_not_interpreted(tmp_path):
    inventory = make_inventory(tmp_path)
    queue = build_review_queue(inventory, tmp_path)
    item = next(item for item in queue["items"] if item["exact_content_group_id"] == "exact-sha256-other")

    assert item["subject"] == ""
    assert item["sender"] == ""
    assert item["reply_to"] == ""
    assert item["authentication_routing_headers"] == {}
    assert "not evidence of phishing or legitimate delivery" in queue["metadata"]["header_note"]


def test_queue_files_and_identifiers_are_deterministic(tmp_path):
    inventory = make_inventory(tmp_path)
    first = build_review_queue(inventory, tmp_path, body_max_chars=20)
    second = build_review_queue(inventory, tmp_path, body_max_chars=20)
    json_one, md_one = tmp_path / "one.json", tmp_path / "one.md"
    json_two, md_two = tmp_path / "two.json", tmp_path / "two.md"
    write_queue(first, json_one, md_one)
    write_queue(second, json_two, md_two)

    assert first == second
    assert json_one.read_bytes() == json_two.read_bytes()
    assert md_one.read_bytes() == md_two.read_bytes()
    assert all(item["body_truncated"] for item in first["items"])
    assert all(len(item["body_text"]) == 20 for item in first["items"])
