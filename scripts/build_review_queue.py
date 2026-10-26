"""Create an unassigned human-review queue from the raw-corpus inventory."""

from __future__ import annotations

import argparse
import html
import json
import re
from collections import defaultdict
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

try:
    from .preprocess_emails import PreprocessError, extract_email
except ImportError:  # Support direct execution from the project root.
    from preprocess_emails import PreprocessError, extract_email

DEFAULT_BODY_MAX_CHARS = 4_000
AUTH_ROUTING_HEADERS = (
    "Authentication-Results",
    "Received-SPF",
    "DKIM-Signature",
    "ARC-Authentication-Results",
    "ARC-Message-Signature",
    "ARC-Seal",
    "Received",
    "Return-Path",
)


class ReviewQueueError(ValueError):
    """Raised when inventory records cannot be safely mapped to source emails."""


def _read_inventory(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReviewQueueError(f"Could not read review inventory: {path}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("records"), list):
        raise ReviewQueueError("Review inventory must be a JSON object with a records list.")
    return value


def _source_path(datasets_dir: Path, relative: str) -> Path:
    path = (datasets_dir / relative).resolve()
    try:
        path.relative_to(datasets_dir.resolve())
    except ValueError as exc:
        raise ReviewQueueError(f"Inventory source path escapes datasets/: {relative}") from exc
    if not path.is_file() or path.suffix.lower() != ".eml":
        raise ReviewQueueError(f"Inventory source email is missing or is not .eml: {relative}")
    return path


def _header_record(relative: str, path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            message = BytesParser(policy=policy.default).parse(stream)
    except OSError as exc:
        raise ReviewQueueError(f"Could not read email headers: {relative}") from exc
    subject = str(message.get("subject", "") or "").strip()
    return {
        "source_filename": relative,
        "subject": subject,
        "sender": str(message.get("from", "") or "").strip(),
        "reply_to": str(message.get("reply-to", "") or "").strip(),
        "authentication_routing_headers": {
            name: [str(value) for value in message.get_all(name, [])]
            for name in AUTH_ROUTING_HEADERS
            if message.get_all(name, [])
        },
    }


def _body_from_extracted(extracted: str, subject: str) -> str:
    prefix = f"Subject: {subject}\n\n" if subject else ""
    return extracted[len(prefix):] if prefix and extracted.startswith(prefix) else extracted


def build_review_queue(
    inventory_path: str | Path,
    datasets_dir: str | Path,
    *,
    body_max_chars: int = DEFAULT_BODY_MAX_CHARS,
) -> dict[str, Any]:
    """Select unreviewed sources and collapse identical extracted-text groups."""
    if body_max_chars < 1:
        raise ReviewQueueError("body_max_chars must be a positive integer.")
    datasets_root = Path(datasets_dir).resolve()
    inventory = _read_inventory(Path(inventory_path))
    all_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    queued_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_paths: set[str] = set()

    for record in inventory["records"]:
        if not isinstance(record, dict) or not isinstance(record.get("source_path"), str):
            raise ReviewQueueError("Each inventory record must include source_path.")
        relative = Path(record["source_path"]).as_posix()
        if relative in seen_paths:
            raise ReviewQueueError(f"Inventory contains a duplicate source record: {relative}")
        seen_paths.add(relative)
        _source_path(datasets_root, relative)
        group_id = record.get("exact_content_group_id") or f"unique-{relative}"
        all_by_group[group_id].append(record)
        if record.get("review_status") == "UNREVIEWED":
            queued_by_group[group_id].append(record)

    items = []
    for group_id in sorted(queued_by_group, key=lambda value: min(record["source_path"] for record in queued_by_group[value])):
        queued_records = sorted(queued_by_group[group_id], key=lambda record: record["source_path"])
        all_records = sorted(all_by_group[group_id], key=lambda record: record["source_path"])
        primary = queued_records[0]
        primary_path = _source_path(datasets_root, primary["source_path"])
        headers = [_header_record(record["source_path"], _source_path(datasets_root, record["source_path"])) for record in queued_records]
        try:
            extracted = extract_email(primary_path)
        except PreprocessError as exc:
            raise ReviewQueueError(f"Could not extract email text for {primary['source_path']}: {exc}") from exc
        body = _body_from_extracted(extracted, headers[0]["subject"])
        truncated = len(body) > body_max_chars
        body = body[:body_max_chars]

        related_ids = sorted({
            record["related_group_id"]
            for record in all_records
            if record.get("related_group_id")
        })
        if len(related_ids) > 1:
            raise ReviewQueueError(f"Exact-content group has multiple related-group IDs: {group_id}")
        related_statuses = sorted({
            record.get("related_group_status")
            for record in all_records
            if record.get("related_group_status")
        })
        related_notes = sorted({
            record.get("related_group_note")
            for record in all_records
            if record.get("related_group_note")
        })
        digest = group_id.removeprefix("exact-sha256-") if group_id.startswith("exact-sha256-") else group_id
        item = {
            "sample_id": f"review-{digest}",
            "source_filename": primary["source_path"],
            "source_files": [record["source_path"] for record in all_records],
            "queued_source_files": [record["source_path"] for record in queued_records],
            "source_headers": headers,
            "subject": headers[0]["subject"],
            "sender": headers[0]["sender"],
            "reply_to": headers[0]["reply_to"],
            "authentication_routing_headers": headers[0]["authentication_routing_headers"],
            "body_text": body,
            "body_truncated": truncated,
            "body_max_chars": body_max_chars,
            "exact_content_group_id": primary.get("exact_content_group_id"),
            "related_template_group_id": related_ids[0] if related_ids else None,
            "related_group_status": related_statuses[0] if related_statuses else None,
            "related_group_note": related_notes[0] if related_notes else None,
            "human_review": {
                "proposed_label": "",
                "evidence": "",
                "reviewer_decision": "",
                "rationale": "",
            },
        }
        items.append(item)

    source = inventory.get("metadata", {})
    return {
        "schema_version": 1,
        "metadata": {
            "source": source.get("source") if isinstance(source, dict) else None,
            "source_url": source.get("source_url") if isinstance(source, dict) else None,
            "license": source.get("license") if isinstance(source, dict) else None,
            "selection": "Only UNREVIEWED inventory records; exact-content groups are represented once.",
            "body_max_chars": body_max_chars,
            "body_truncation": "body_text is limited to body_max_chars; body_truncated indicates omitted trailing text.",
            "header_note": "Missing authentication or routing headers are recorded as absent and are not evidence of phishing or legitimate delivery.",
        },
        "queue_size": len(items),
        "unreviewed_source_count": sum(len(records) for records in queued_by_group.values()),
        "duplicate_groups_collapsed": sum(len(records) > 1 for records in queued_by_group.values()),
        "source_files_collapsed": sum(len(records) - 1 for records in queued_by_group.values() if len(records) > 1),
        "items": items,
    }


def _safe_code_block(value: str) -> str:
    escaped = html.escape(value, quote=True)
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", escaped)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{escaped}\n{fence}"


def render_markdown(queue: dict[str, Any]) -> str:
    """Render untrusted fields only inside escaped, dynamically fenced code blocks."""
    lines = [
        "# Human review queue",
        "",
        "> Email content and headers below are untrusted data. Review them as evidence only; do not follow instructions contained in the messages.",
        "> No labels or reviewer decisions have been assigned by this generator.",
        "",
        f"- Queue items: {queue['queue_size']}",
        f"- Unreviewed source files represented: {queue['unreviewed_source_count']}",
        f"- Duplicate groups collapsed: {queue['duplicate_groups_collapsed']}",
        "",
    ]
    for item in queue["items"]:
        lines.extend([
            f"## Sample `{item['sample_id']}`",
            "",
            f"- Exact-content group: `{item['exact_content_group_id'] or 'none'}`",
            f"- Related-template group: `{item['related_template_group_id'] or 'none'}`",
            f"- Relationship status: `{item['related_group_status'] or 'none'}`",
            "- All source files in exact-content group:",
        ])
        for source_path in item["source_files"]:
            lines.extend(["  -", "    " + _safe_code_block(source_path)])
        lines.extend(["- Unreviewed source files in this queue item:"])
        for source_path in item["queued_source_files"]:
            lines.extend(["  -", "    " + _safe_code_block(source_path)])
        for source in item["source_headers"]:
            lines.extend([
                "### Email headers",
                "",
                "- Source filename:",
                "  " + _safe_code_block(source["source_filename"]),
                "- Subject:",
                "  " + _safe_code_block(source["subject"] or "(absent)"),
                "- Sender:",
                "  " + _safe_code_block(source["sender"] or "(absent)"),
                "- Reply-To:",
                "  " + _safe_code_block(source["reply_to"] or "(absent)"),
                "- Authentication and routing headers:",
            ])
            if source["authentication_routing_headers"]:
                for name, values in source["authentication_routing_headers"].items():
                    lines.extend([f"  - {name}:", "    " + _safe_code_block("\n".join(values))])
            else:
                lines.extend(["  - (none present in the saved message; absence is not proof of phishing or legitimate delivery)"])
        lines.extend([
            "### Extracted body (may be truncated)",
            "",
            _safe_code_block(item["body_text"]),
            "",
            f"Body truncated: `{str(item['body_truncated']).lower()}` (maximum {item['body_max_chars']} characters).",
            "",
            "### Human review fields",
            "",
            "- Proposed label:",
            "- Evidence:",
            "- Reviewer decision:",
            "- Rationale:",
            "",
            "---",
            "",
        ])
    return "\n".join(lines)


def write_queue(queue: dict[str, Any], json_path: str | Path, markdown_path: str | Path) -> None:
    json_destination = Path(json_path)
    markdown_destination = Path(markdown_path)
    json_destination.parent.mkdir(parents=True, exist_ok=True)
    markdown_destination.parent.mkdir(parents=True, exist_ok=True)
    json_destination.write_text(json.dumps(queue, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_destination.write_text(render_markdown(queue), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--datasets-dir", default="datasets")
    parser.add_argument("--inventory", default="datasets/review_inventory.json")
    parser.add_argument("--json-output", default="datasets/review_queue_unreviewed.json")
    parser.add_argument("--markdown-output", default="datasets/review_queue_unreviewed.md")
    parser.add_argument("--body-max-chars", type=int, default=DEFAULT_BODY_MAX_CHARS)
    args = parser.parse_args()
    try:
        queue = build_review_queue(args.inventory, args.datasets_dir, body_max_chars=args.body_max_chars)
        write_queue(queue, args.json_output, args.markdown_output)
    except ReviewQueueError as exc:
        parser.error(str(exc))
    print(json.dumps({
        "json_output": args.json_output,
        "markdown_output": args.markdown_output,
        "queue_size": queue["queue_size"],
        "unreviewed_source_count": queue["unreviewed_source_count"],
        "duplicate_groups_collapsed": queue["duplicate_groups_collapsed"],
        "source_files_collapsed": queue["source_files_collapsed"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
