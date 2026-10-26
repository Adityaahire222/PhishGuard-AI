"""Build a deterministic review and duplicate inventory for the raw .eml corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    from .preprocess_emails import LABELS, PreprocessError, extract_email, load_manifest
except ImportError:  # Support direct execution as documented in the README.
    from preprocess_emails import LABELS, PreprocessError, extract_email, load_manifest

REVIEW_STATUSES = {"APPROVED", "REJECTED"}
CORPUS_RELATIVE_DIR = Path("raw/phishing-2015-eml")
REVIEW_FILE = "review_decisions_batch_01.json"
MANIFEST_FILE = "manifest.json"

REVIEW_SUPPORTED_RELATIONSHIPS = {
    frozenset(("message-000004.eml", "message-000005.eml")): {
        "group_id": "review-related-amazon-template-000004-000005",
        "note": "Review notes describe a shared Amazon-themed template/infrastructure; campaign relationship is plausible, not verified.",
    },
    frozenset(("message-000007.eml", "message-000008.eml")): {
        "group_id": "review-related-apple-template-000007-000008",
        "note": "Review notes describe closely matching Apple Store messages; shared campaign is likely but not independently verified.",
    },
}


class InventoryError(ValueError):
    """Raised when manifest, review decisions, and source files disagree."""


def _read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"Could not read {description}: {path}") from exc
    if not isinstance(value, dict):
        raise InventoryError(f"{description} must contain a JSON object.")
    return value


def _manifest_labels(datasets_dir: Path, manifest_path: Path) -> dict[str, str]:
    try:
        manifest = load_manifest(manifest_path)
    except PreprocessError as exc:
        raise InventoryError(f"Invalid manifest: {exc}") from exc

    labels: dict[str, str] = {}

    def add(path: Path, label: str) -> None:
        try:
            relative = path.resolve().relative_to(datasets_dir.resolve()).as_posix()
        except ValueError as exc:
            raise InventoryError(f"Manifest path resolves outside datasets/: {path}") from exc
        if relative in labels and labels[relative] != label:
            raise InventoryError(
                f"Manifest assigns conflicting labels to {relative}: {labels[relative]} and {label}."
            )
        labels[relative] = label

    for source in manifest["sources"]:
        directory = (datasets_dir / source["path"]).resolve()
        if not directory.is_dir():
            raise InventoryError(f"Manifest source directory does not exist: {source['path']}")
        for email_path in sorted(directory.rglob("*.eml")):
            add(email_path, source["label"])
    for entry in manifest["files"]:
        email_path = (datasets_dir / entry["path"]).resolve()
        if not email_path.is_file():
            raise InventoryError(f"Manifest email file does not exist: {entry['path']}")
        add(email_path, entry["label"])
    return labels


def _review_decisions(datasets_dir: Path, review_path: Path) -> dict[str, dict[str, Any]]:
    data = _read_json(review_path, "review decisions")
    decisions = data.get("decisions")
    if not isinstance(decisions, list):
        raise InventoryError("Review decisions must include a 'decisions' list.")

    indexed: dict[str, dict[str, Any]] = {}
    for number, decision in enumerate(decisions, start=1):
        if not isinstance(decision, dict) or not isinstance(decision.get("filename"), str):
            raise InventoryError(f"Review decision {number} must include a filename.")
        raw_name = Path(decision["filename"]).as_posix()
        relative = raw_name if raw_name.startswith(CORPUS_RELATIVE_DIR.as_posix() + "/") else (CORPUS_RELATIVE_DIR / raw_name).as_posix()
        if relative in indexed:
            raise InventoryError(f"Duplicate review decision for {relative}.")
        status = decision.get("review_status")
        if status not in REVIEW_STATUSES:
            raise InventoryError(f"Unsupported review status for {relative}: {status!r}.")
        label = decision.get("approved_label")
        if status == "APPROVED" and label not in LABELS:
            raise InventoryError(f"Approved review decision for {relative} lacks a supported approved_label.")
        if status == "REJECTED" and label is not None:
            raise InventoryError(f"Rejected review decision for {relative} must not have an approved_label.")
        indexed[relative] = decision
    return indexed


def build_inventory(datasets_dir: str | Path) -> dict[str, Any]:
    """Build inventory records using extraction identical to preprocessing."""
    datasets_root = Path(datasets_dir).resolve()
    manifest_path = datasets_root / MANIFEST_FILE
    review_path = datasets_root / REVIEW_FILE
    raw_dir = datasets_root / CORPUS_RELATIVE_DIR
    if not raw_dir.is_dir():
        raise InventoryError(f"Raw corpus directory does not exist: {raw_dir}")

    manifest_labels = _manifest_labels(datasets_root, manifest_path)
    decisions = _review_decisions(datasets_root, review_path)
    files = sorted(path for path in raw_dir.rglob("*.eml") if path.is_file())
    relative_paths = [(CORPUS_RELATIVE_DIR / path.relative_to(raw_dir)).as_posix() for path in files]
    source_set = set(relative_paths)

    missing_manifest_files = sorted(set(manifest_labels) - source_set)
    missing_review_files = sorted(set(decisions) - source_set)
    if missing_manifest_files or missing_review_files:
        raise InventoryError(
            "Inventory inputs reference missing source files: "
            f"manifest={missing_manifest_files}, review_decisions={missing_review_files}."
        )

    for relative, label in manifest_labels.items():
        decision = decisions.get(relative)
        if decision is None or decision["review_status"] != "APPROVED":
            raise InventoryError(f"Manifest label for {relative} lacks an APPROVED human review decision.")
        if decision["approved_label"] != label:
            raise InventoryError(
                f"Manifest/review label mismatch for {relative}: {label} != {decision['approved_label']}."
            )
    for relative, decision in decisions.items():
        if decision["review_status"] == "APPROVED" and relative not in manifest_labels:
            raise InventoryError(f"Approved review decision for {relative} is missing from the manifest.")
        if decision["review_status"] == "REJECTED" and relative in manifest_labels:
            raise InventoryError(f"Rejected review decision for {relative} must not appear in the manifest.")

    extracted: dict[str, str] = {}
    hash_paths: dict[str, list[str]] = defaultdict(list)
    for path, relative in zip(files, relative_paths):
        try:
            text = extract_email(path)
        except PreprocessError as exc:
            raise InventoryError(f"Could not extract normalized text from {relative}: {exc}") from exc
        extracted[relative] = text
        if text:
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            hash_paths[digest].append(relative)

    duplicate_hashes = {digest for digest, group in hash_paths.items() if len(group) > 1}
    duplicate_label_conflicts: list[dict[str, Any]] = []
    for digest in sorted(duplicate_hashes):
        approved = {
            manifest_labels[path]
            for path in hash_paths[digest]
            if path in manifest_labels
        }
        if len(approved) > 1:
            duplicate_label_conflicts.append({"group_id": f"exact-sha256-{digest}", "labels": sorted(approved), "source_paths": sorted(hash_paths[digest])})

    records: list[dict[str, Any]] = []
    for relative in relative_paths:
        decision = decisions.get(relative)
        label = manifest_labels.get(relative)
        if decision is None:
            status = "UNREVIEWED"
            evidence_note = "No human review decision or approved manifest label; no label assigned."
            review_ref = None
            manifest_ref = None
        else:
            status = decision["review_status"]
            evidence_note = decision.get("rationale", "See the referenced human review decision.")
            review_ref = f"{REVIEW_FILE}#decisions/{Path(relative).name}"
            manifest_ref = f"{MANIFEST_FILE}#files/{relative}" if label else None

        text = extracted[relative]
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None
        exact_group_id = f"exact-sha256-{digest}" if digest else None
        relationship = None
        for pair, metadata in REVIEW_SUPPORTED_RELATIONSHIPS.items():
            if Path(relative).name in pair:
                relationship = metadata
                break
        records.append({
            "source_path": relative,
            "review_status": status,
            "approved_label": label,
            "exact_content_group_id": exact_group_id,
            "related_group_id": relationship["group_id"] if relationship else None,
            "related_group_status": "REVIEW_SUPPORTED_NOT_VERIFIED" if relationship else None,
            "related_group_note": relationship["note"] if relationship else None,
            "review_record_ref": review_ref,
            "manifest_record_ref": manifest_ref,
            "evidence_note": evidence_note,
        })

    manifest_data = _read_json(manifest_path, "manifest")
    metadata = manifest_data.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    return {
        "schema_version": 1,
        "metadata": {
            "source": metadata.get("source"),
            "source_url": metadata.get("source_url"),
            "license": metadata.get("license"),
            "conversion": metadata.get("conversion"),
            "normalization": "scripts.preprocess_emails.extract_email output, compared byte-for-byte as Unicode text; SHA-256 of UTF-8 text forms stable group IDs.",
            "grouping_limitations": "Exact text equality only; near duplicates and campaign families are not inferred. Related groups are limited to documented human-review notes and are not independently verified.",
        },
        "integrity": {
            "source_file_count": len(files),
            "inventory_record_count": len(records),
            "unreviewed_source_count": sum(record["review_status"] == "UNREVIEWED" for record in records),
            "missing_or_inconsistent_records": [],
            "approved_duplicate_label_conflicts": duplicate_label_conflicts,
        },
        "records": records,
    }


def write_inventory(inventory: dict[str, Any], output_path: str | Path) -> None:
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--datasets-dir", default="datasets", help="Dataset root containing raw/, manifest.json, and review decisions")
    parser.add_argument("--output", default="datasets/review_inventory.json", help="Output JSON inventory path")
    args = parser.parse_args()
    try:
        inventory = build_inventory(args.datasets_dir)
        write_inventory(inventory, args.output)
    except InventoryError as exc:
        parser.error(str(exc))

    records = inventory["records"]
    duplicate_counts = Counter(record["exact_content_group_id"] for record in records if record["exact_content_group_id"])
    duplicate_groups = {group for group, count in duplicate_counts.items() if count > 1}
    result = {
        "output": str(Path(args.output)),
        "total_source_files": len(records),
        "review_status_counts": dict(Counter(record["review_status"] for record in records)),
        "approved_label_counts": dict(Counter(record["approved_label"] for record in records if record["approved_label"])),
        "exact_duplicate_group_count": len(duplicate_groups),
        "files_in_exact_duplicate_groups": sum(duplicate_counts[group] for group in duplicate_groups),
        "related_group_count": len({record["related_group_id"] for record in records if record["related_group_id"]}),
        "missing_or_inconsistent_records": inventory["integrity"]["missing_or_inconsistent_records"],
        "approved_duplicate_label_conflicts": inventory["integrity"]["approved_duplicate_label_conflicts"],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
