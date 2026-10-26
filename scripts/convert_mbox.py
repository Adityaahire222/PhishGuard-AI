"""Split an mbox archive into individual .eml files without opening content."""

from __future__ import annotations

import argparse
import mailbox
import sys
from email.message import Message
from pathlib import Path

INTERNAL_NOTICE_SUBJECT = "DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA"


def convert_mbox(input_path: str | Path, output_dir: str | Path) -> dict[str, int]:
    """Write each non-notice mbox record as a separate .eml file."""
    source = Path(input_path)
    destination = Path(output_dir)
    counts = {"messages_processed": 0, "internal_notices_skipped": 0, "failures": 0}
    destination.mkdir(parents=True, exist_ok=True)
    try:
        archive = mailbox.mbox(source, create=False)
    except (OSError, mailbox.Error) as exc:
        raise ValueError(f"Could not open mbox file: {source}") from exc

    try:
        for index, message in enumerate(archive, start=1):
            counts["messages_processed"] += 1
            if str(message.get("subject", "")).strip() == INTERNAL_NOTICE_SUBJECT:
                counts["internal_notices_skipped"] += 1
                continue
            try:
                output_path = destination / f"message-{index:06d}.eml"
                output_path.write_bytes(serialize_message(message))
            except (OSError, mailbox.Error, ValueError):
                counts["failures"] += 1
    finally:
        archive.close()
    return counts


def serialize_message(message: Message) -> bytes:
    """Serialize one parsed message as RFC-style bytes, including headers."""
    return message.as_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="Path to an mbox file")
    parser.add_argument("output_dir", help="Directory for individual .eml files")
    args = parser.parse_args()
    try:
        counts = convert_mbox(args.input, args.output_dir)
    except ValueError as exc:
        parser.error(str(exc))
    print(
        "Messages processed: {messages_processed}; internal notices skipped: "
        "{internal_notices_skipped}; failures: {failures}".format(**counts),
        file=sys.stdout,
    )
    return 1 if counts["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
