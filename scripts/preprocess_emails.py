"""Convert manifest-labeled .eml messages to the PhishGuard evaluation CSV format.

This tool parses message text only. It never fetches URLs, saves attachments, or
executes email content. See datasets/README.md for the manifest structure.
"""

from __future__ import annotations

import argparse
import csv
from html.parser import HTMLParser
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

MAX_CHARS = 20_000
LABELS = {"PHISHING", "LEGITIMATE", "SUSPICIOUS", "INCONCLUSIVE"}


class PreprocessError(ValueError):
    """Raised for invalid manifests or unreadable input messages."""


class _VisibleTextParser(HTMLParser):
    """Collect readable HTML text while discarding non-visible element content."""

    _BLOCK_TAGS = {"address", "article", "blockquote", "br", "div", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "ol", "p", "section", "table", "td", "th", "tr", "ul"}
    _HIDDEN_TAGS = {"head", "script", "style", "template", "noscript", "svg", "iframe", "object", "embed"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden_depth = 0
        self.open_tags: list[tuple[str, bool]] = []
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "").lower() for name, value in attrs}
        hidden = (
            tag in self._HIDDEN_TAGS
            or "hidden" in attributes
            or attributes.get("aria-hidden") == "true"
            or bool(re.search(r"(?:display\s*:\s*none|visibility\s*:\s*hidden)", attributes.get("style", "")))
        )
        self.open_tags.append((tag, hidden))
        if hidden:
            self.hidden_depth += 1
        if self.hidden_depth == 0 and tag in self._BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.open_tags) - 1, -1, -1):
            open_tag, hidden = self.open_tags[index]
            if open_tag == tag:
                removed = self.open_tags[index:]
                del self.open_tags[index:]
                self.hidden_depth -= sum(1 for _, is_hidden in removed if is_hidden)
                break
        if self.hidden_depth == 0 and tag in self._BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self.hidden_depth == 0:
            self.parts.append(data)

    def text(self) -> str:
        lines = [re.sub(r"[ \t\f\v]+", " ", line).strip() for line in "".join(self.parts).splitlines()]
        return "\n".join(line for line in lines if line).strip()


def _decoded_text(part: Any) -> str:
    """Decode one text MIME part using its charset, replacing malformed bytes."""
    try:
        content = part.get_content()
    except (LookupError, UnicodeError, KeyError):
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            content = payload.decode(charset, errors="replace")
        except LookupError:
            content = payload.decode("utf-8", errors="replace")
    return content if isinstance(content, str) else ""


def _html_to_text(content: str) -> str:
    parser = _VisibleTextParser()
    parser.feed(content)
    parser.close()
    return parser.text()


def load_manifest(path: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Load directory sources and/or explicitly labeled individual files."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreprocessError("Could not read a valid UTF-8 JSON manifest.") from exc
    if not isinstance(data, dict):
        raise PreprocessError("Manifest must be a JSON object.")
    sources = data.get("sources", [])
    files = data.get("files", [])
    if not isinstance(sources, list) or not isinstance(files, list):
        raise PreprocessError("Manifest 'sources' and 'files' entries must be lists.")
    if not sources and not files:
        raise PreprocessError("Manifest must contain at least one 'sources' or 'files' entry.")
    validated_sources = []
    for number, source in enumerate(sources, start=1):
        if not isinstance(source, dict) or not isinstance(source.get("path"), str):
            raise PreprocessError(f"Manifest source {number} must include a path.")
        label = source.get("label")
        if not isinstance(label, str) or label.strip().upper() not in LABELS:
            raise PreprocessError(f"Manifest source {number} must explicitly supply a supported label.")
        validated_sources.append({"path": source["path"], "label": label.strip().upper()})
    validated_files = []
    for number, entry in enumerate(files, start=1):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise PreprocessError(f"Manifest file entry {number} must include a path.")
        file_path = Path(entry["path"])
        if file_path.is_absolute() or file_path.drive or file_path.root or file_path.suffix.lower() != ".eml":
            raise PreprocessError(f"Manifest file entry {number} path must be a relative .eml path.")
        label = entry.get("label")
        if not isinstance(label, str) or label.strip().upper() not in LABELS:
            raise PreprocessError(f"Manifest file entry {number} must explicitly supply a supported label.")
        validated_files.append({"path": entry["path"], "label": label.strip().upper()})
    return {"sources": validated_sources, "files": validated_files}


def extract_email(path: str | Path) -> str:
    """Extract subject and readable body text; plain text wins over HTML."""
    try:
        with Path(path).open("rb") as stream:
            message = BytesParser(policy=policy.default).parse(stream)
    except OSError as exc:
        raise PreprocessError(f"Could not read email file: {path}") from exc

    subject = str(message.get("subject", "") or "").strip()
    plain_bodies: list[str] = []
    html_bodies: list[str] = []
    parts = message.walk() if message.is_multipart() else (message,)
    for part in parts:
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type().lower()
        if content_type not in {"text/plain", "text/html"}:
            continue
        content = _decoded_text(part)
        if content.strip():
            if content_type == "text/plain":
                plain_bodies.append(content.strip())
            else:
                html_bodies.append(_html_to_text(content))
    bodies = [body for body in plain_bodies if body.strip()]
    if not bodies:
        bodies = [body for body in html_bodies if body.strip()]
    pieces = ([f"Subject: {subject}"] if subject else []) + bodies
    return "\n\n".join(pieces).strip()


def preprocess(manifest_path: str | Path, output_path: str | Path) -> dict[str, int]:
    """Process labeled sources and retain source filenames when exact text repeats."""
    manifest = Path(manifest_path).resolve()
    rows: list[dict[str, str]] = []
    stats = {"files_seen": 0, "empty_excluded": 0, "too_long_excluded": 0, "duplicates_excluded": 0, "rows_written": 0}
    manifest_data = load_manifest(manifest)
    labeled_paths: dict[Path, dict[str, Any]] = {}

    def add_labeled_path(email_path: Path, label: str, source_id: str) -> None:
        resolved_path = email_path.resolve()
        existing = labeled_paths.get(resolved_path)
        if existing is not None and existing["label"] != label:
            existing_label = existing["label"]
            raise PreprocessError(f"Conflicting labels for file {resolved_path}: {existing_label} and {label}.")
        if existing is None:
            labeled_paths[resolved_path] = {"label": label, "source_ids": [source_id]}
        elif source_id not in existing["source_ids"]:
            existing["source_ids"].append(source_id)

    for source in manifest_data["sources"]:
        source_path = (manifest.parent / source["path"]).resolve()
        if not source_path.is_dir():
            raise PreprocessError(f"Source directory does not exist: {source['path']}")
        # Each directory is traversed independently; its manifest label is preserved.
        for email_path in sorted(source_path.rglob("*.eml")):
            relative_file = email_path.relative_to(source_path)
            source_id = (Path(source["path"]) / relative_file).as_posix()
            add_labeled_path(email_path, source["label"], source_id)
    for entry in manifest_data["files"]:
        email_path = (manifest.parent / entry["path"]).resolve()
        if not email_path.is_file():
            raise PreprocessError(f"Manifest email file does not exist: {entry['path']}")
        add_labeled_path(email_path, entry["label"], Path(entry["path"]).as_posix())

    text_to_row: dict[str, dict[str, str]] = {}
    for email_path, source in labeled_paths.items():
        stats["files_seen"] += 1
        text = extract_email(email_path)
        if not text:
            stats["empty_excluded"] += 1
            continue
        if len(text) > MAX_CHARS:
            stats["too_long_excluded"] += 1
            continue
        if text in text_to_row:
            existing_row = text_to_row[text]
            if existing_row["label"] != source["label"]:
                existing_sources = json.loads(existing_row["source_files"])
                raise PreprocessError(
                    "Conflicting labels for identical extracted email text: "
                    f"{existing_row['label']} from {existing_sources} and "
                    f"{source['label']} from {source['source_ids']}. "
                    "Resolve the labels in the manifest before preprocessing."
                )
            stats["duplicates_excluded"] += 1
            source_files = json.loads(existing_row["source_files"])
            for source_id in source["source_ids"]:
                if source_id not in source_files:
                    source_files.append(source_id)
            existing_row["source_files"] = json.dumps(source_files, ensure_ascii=False)
            continue
        row = {
            "email_text": text,
            "label": source["label"],
            "source_files": json.dumps(source["source_ids"], ensure_ascii=False),
        }
        rows.append(row)
        text_to_row[text] = row
    stats["rows_written"] = len(rows)
    if not rows:
        raise PreprocessError(f"No eligible emails remain; exclusion statistics: {json.dumps(stats, sort_keys=True)}")
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["email_text", "label", "source_files"])
        writer.writeheader()
        writer.writerows(rows)
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="JSON manifest with explicitly labeled source directories")
    parser.add_argument("output", help="Output UTF-8 CSV path")
    args = parser.parse_args()
    try:
        stats = preprocess(args.manifest, args.output)
    except PreprocessError as exc:
        parser.error(str(exc))
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
