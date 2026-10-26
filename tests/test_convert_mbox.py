import mailbox
import shutil
from pathlib import Path
from uuid import uuid4
from email.message import EmailMessage

from scripts.convert_mbox import INTERNAL_NOTICE_SUBJECT, convert_mbox


def add_message(archive, *, sender, subject, body):
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "recipient@example.test"
    message["Subject"] = subject
    message["Message-ID"] = f"<{subject.replace(' ', '-') }@example.test>"
    message.set_content(body)
    archive.add(message)


def test_splits_messages_preserves_headers_and_skips_internal_notice():
    tmp_path = Path.cwd() / f"mbox-test-{uuid4().hex}"
    tmp_path.mkdir()
    try:
        _test_splits_messages_preserves_headers_and_skips_internal_notice(tmp_path)
    finally:
        shutil.rmtree(tmp_path)


def _test_splits_messages_preserves_headers_and_skips_internal_notice(tmp_path):
    source = tmp_path / "source.mbox"
    archive = mailbox.mbox(source)
    add_message(archive, sender="system@example.test", subject=INTERNAL_NOTICE_SUBJECT, body="not a real message")
    add_message(archive, sender="alice@example.test", subject="First", body="first body")
    add_message(archive, sender="bob@example.test", subject="Second", body="second body")
    archive.flush()
    archive.close()

    output = tmp_path / "eml"
    counts = convert_mbox(source, output)
    files = sorted(output.glob("*.eml"))
    assert len(files) == 2
    assert counts == {"messages_processed": 3, "internal_notices_skipped": 1, "failures": 0}
    parsed = [mailbox.mboxMessage(file.read_bytes()) for file in files]
    assert [message["Subject"] for message in parsed] == ["First", "Second"]
    assert [message["Message-ID"] for message in parsed] == ["<First@example.test>", "<Second@example.test>"]


def test_keeps_normal_message_with_mailer_daemon_from_header():
    tmp_path = Path.cwd() / f"mbox-test-{uuid4().hex}"
    tmp_path.mkdir()
    try:
        _test_keeps_normal_message_with_mailer_daemon_from_header(tmp_path)
    finally:
        shutil.rmtree(tmp_path)


def _test_keeps_normal_message_with_mailer_daemon_from_header(tmp_path):
    source = tmp_path / "source.mbox"
    archive = mailbox.mbox(source)
    add_message(archive, sender="MAILER-DAEMON@example.test", subject="Delivery report", body="Ordinary report body")
    archive.flush()
    archive.close()

    output = tmp_path / "eml"
    counts = convert_mbox(source, output)
    files = list(output.glob("*.eml"))
    assert len(files) == 1
    message = mailbox.mboxMessage(files[0].read_bytes())
    assert message["From"] == "MAILER-DAEMON@example.test"
    assert message["Subject"] == "Delivery report"
    assert counts == {"messages_processed": 1, "internal_notices_skipped": 0, "failures": 0}
