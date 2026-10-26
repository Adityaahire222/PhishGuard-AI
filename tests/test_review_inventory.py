import json
from email.message import EmailMessage

import pytest

from scripts.build_review_inventory import InventoryError, build_inventory, write_inventory


def write_eml(path, subject, body):
    message = EmailMessage()
    message["Subject"] = subject
    message.set_content(body)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(message.as_bytes())


def make_inventory_sources(datasets_dir):
    raw_dir = datasets_dir / "raw" / "phishing-2015-eml"
    messages = {
        "message-000002.eml": ("Same", "duplicate body", "APPROVED", "PHISHING"),
        "message-000003.eml": ("Same", "duplicate body", "APPROVED", "PHISHING"),
        "message-000004.eml": ("Amazon", "template A", "APPROVED", "PHISHING"),
        "message-000005.eml": ("Amazon", "template B", "APPROVED", "PHISHING"),
        "message-000006.eml": ("Unreadable", "image only", "REJECTED", None),
        "message-000007.eml": ("Apple", "template C", "APPROVED", "PHISHING"),
        "message-000008.eml": ("Apple", "template D", "APPROVED", "PHISHING"),
        "message-000009.eml": ("Mailbox", "capacity warning", "APPROVED", "SUSPICIOUS"),
        "message-000010.eml": ("Account", "update account", "APPROVED", "PHISHING"),
        "message-000012.eml": ("Unreviewed", "no assigned label", None, None),
    }
    manifest_files = []
    decisions = []
    for filename, (subject, body, status, label) in messages.items():
        write_eml(raw_dir / filename, subject, body)
        if status == "APPROVED":
            manifest_files.append({"path": f"raw/phishing-2015-eml/{filename}", "label": label})
        if status:
            decisions.append({
                "filename": filename,
                "review_status": status,
                "approved_label": label,
                "rationale": f"Recorded human decision for {filename}.",
            })
    (datasets_dir / "manifest.json").write_text(json.dumps({
        "files": manifest_files,
        "metadata": {"source": "Fixture corpus", "license": "CC BY 4.0"},
    }), encoding="utf-8")
    (datasets_dir / "review_decisions_batch_01.json").write_text(json.dumps({"decisions": decisions}), encoding="utf-8")
    return messages


def test_inventory_represents_each_source_once_and_agrees_with_approved_records(tmp_path):
    messages = make_inventory_sources(tmp_path)
    inventory = build_inventory(tmp_path)
    records = inventory["records"]
    by_name = {record["source_path"].rsplit("/", 1)[-1]: record for record in records}

    assert len(records) == len(messages)
    assert len({record["source_path"] for record in records}) == len(messages)
    for filename, (_, _, status, label) in messages.items():
        record = by_name[filename]
        assert record["review_status"] == (status or "UNREVIEWED")
        assert record["approved_label"] == label
        if status:
            assert "review_decisions_batch_01.json#decisions/" in record["review_record_ref"]
        else:
            assert record["review_record_ref"] is None
            assert "no label assigned" in record["evidence_note"]
    assert inventory["integrity"]["missing_or_inconsistent_records"] == []


def test_exact_duplicate_groups_are_stable_and_do_not_join_distinct_text(tmp_path):
    make_inventory_sources(tmp_path)
    first = build_inventory(tmp_path)
    second = build_inventory(tmp_path)
    first_path = tmp_path / "inventory-one.json"
    second_path = tmp_path / "inventory-two.json"
    write_inventory(first, first_path)
    write_inventory(second, second_path)
    assert first_path.read_bytes() == second_path.read_bytes()

    records = {record["source_path"].rsplit("/", 1)[-1]: record for record in first["records"]}
    assert records["message-000002.eml"]["exact_content_group_id"] == records["message-000003.eml"]["exact_content_group_id"]
    assert records["message-000002.eml"]["exact_content_group_id"].startswith("exact-sha256-")
    assert records["message-000009.eml"]["exact_content_group_id"] != records["message-000010.eml"]["exact_content_group_id"]


def test_review_supported_related_groups_are_marked_unverified(tmp_path):
    make_inventory_sources(tmp_path)
    inventory = build_inventory(tmp_path)
    records = {record["source_path"].rsplit("/", 1)[-1]: record for record in inventory["records"]}

    assert records["message-000004.eml"]["related_group_id"] == records["message-000005.eml"]["related_group_id"]
    assert records["message-000007.eml"]["related_group_id"] == records["message-000008.eml"]["related_group_id"]
    for filename in ("message-000004.eml", "message-000005.eml", "message-000007.eml", "message-000008.eml"):
        assert records[filename]["related_group_status"] == "REVIEW_SUPPORTED_NOT_VERIFIED"
        assert "not verified" in records[filename]["related_group_note"] or "not independently verified" in records[filename]["related_group_note"]
    assert records["message-000009.eml"]["related_group_id"] is None


def test_manifest_label_mismatch_with_review_decision_is_rejected(tmp_path):
    make_inventory_sources(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["label"] = "LEGITIMATE"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(InventoryError, match="Manifest/review label mismatch"):
        build_inventory(tmp_path)
