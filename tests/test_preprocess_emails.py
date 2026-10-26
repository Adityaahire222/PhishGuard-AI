import csv
import json
from email.message import EmailMessage

import pytest

from scripts.preprocess_emails import MAX_CHARS, PreprocessError, extract_email, preprocess


def write_eml(path, *, subject="Notice", body="Hello", charset="utf-8", attachment=None):
    message = EmailMessage()
    message["Subject"] = subject
    message.set_content(body, charset=charset)
    if attachment is not None:
        message.add_attachment(attachment.encode("utf-8"), maintype="application", subtype="octet-stream", filename="ignored.bin")
    path.write_bytes(message.as_bytes())


def write_html_eml(path, html, *, plain=None):
    message = EmailMessage()
    message["Subject"] = "HTML notice"
    if plain is None:
        message.set_content(html, subtype="html", charset="utf-8")
    else:
        message.set_content(plain, charset="utf-8")
        message.add_alternative(html, subtype="html", charset="utf-8")
    path.write_bytes(message.as_bytes())


def make_manifest(root, sources):
    path = root / "manifest.json"
    path.write_text(json.dumps(sources), encoding="utf-8")
    return path


def test_extracts_subject_plain_body_and_decodes_charset(tmp_path):
    path = tmp_path / "mail.eml"
    write_eml(path, subject="Café, update", body="Résumé body", charset="iso-8859-1", attachment="ignore me")
    extracted = extract_email(path)
    assert extracted == "Subject: Café, update\n\nRésumé body"
    assert "ignore me" not in extracted


def test_extracts_readable_text_from_html_only_message(tmp_path):
    path = tmp_path / "html-only.eml"
    write_html_eml(path, "<html><body><p>Hello <b>there</b>.</p><p>Next line &amp; more.</p></body></html>")
    assert extract_email(path) == "Subject: HTML notice\n\nHello there.\nNext line & more."


def test_prefers_plain_text_when_plain_and_html_are_present(tmp_path):
    path = tmp_path / "alternative.eml"
    write_html_eml(path, "<p>HTML version</p>", plain="Plain version")
    assert extract_email(path) == "Subject: HTML notice\n\nPlain version"


def test_html_fallback_removes_scripts_styles_and_hidden_content(tmp_path):
    path = tmp_path / "unsafe-html.eml"
    write_html_eml(
        path,
        "<html><head><style>.x { display:none }</style></head><body>Visible"
        "<script>alert('hidden')</script><div hidden>Hidden block</div>"
        "<span style='display:none'>Hidden style</span><p>Text</p></body></html>",
    )
    extracted = extract_email(path)
    assert "Visible" in extracted and "Text" in extracted
    assert "alert" not in extracted
    assert "Hidden block" not in extracted
    assert "Hidden style" not in extracted


def test_manifest_labels_sources_separately_and_removes_exact_duplicates(tmp_path):
    phishing = tmp_path / "phishing"
    legitimate = tmp_path / "legitimate"
    phishing.mkdir()
    legitimate.mkdir()
    write_eml(phishing / "one.eml", subject="Same", body="same body")
    write_eml(phishing / "duplicate.eml", subject="Same", body="same body")
    write_eml(legitimate / "one.eml", subject="Other", body="different body")
    manifest = make_manifest(tmp_path, {"sources": [
        {"path": "phishing", "label": "PHISHING"},
        {"path": "legitimate", "label": "LEGITIMATE"},
    ]})
    output = tmp_path / "out.csv"
    stats = preprocess(manifest, output)
    with output.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert rows == [
        {"email_text": "Subject: Same\n\nsame body", "label": "PHISHING", "source_files": '["phishing/duplicate.eml", "phishing/one.eml"]'},
        {"email_text": "Subject: Other\n\ndifferent body", "label": "LEGITIMATE", "source_files": '["legitimate/one.eml"]'},
    ]
    assert stats["duplicates_excluded"] == 1
    assert stats["rows_written"] == 2


def test_identical_extracted_text_with_conflicting_labels_fails_before_output(tmp_path):
    phishing = tmp_path / "phishing"
    legitimate = tmp_path / "legitimate"
    phishing.mkdir()
    legitimate.mkdir()
    write_eml(phishing / "known.eml", subject="Same", body="same content")
    write_eml(legitimate / "conflict.eml", subject="Same", body="same content")
    manifest = make_manifest(tmp_path, {"sources": [
        {"path": "phishing", "label": "PHISHING"},
        {"path": "legitimate", "label": "LEGITIMATE"},
    ]})
    output = tmp_path / "out.csv"

    with pytest.raises(PreprocessError) as error:
        preprocess(manifest, output)

    message = str(error.value)
    assert "identical extracted email text" in message
    assert "PHISHING" in message and "LEGITIMATE" in message
    assert "phishing/known.eml" in message
    assert "legitimate/conflict.eml" in message
    assert "Resolve the labels in the manifest" in message
    assert not output.exists()


def test_legacy_sources_and_per_file_manifest_formats_work_together(tmp_path):
    legacy_source = tmp_path / "legacy"
    individual_source = tmp_path / "individual"
    legacy_source.mkdir()
    individual_source.mkdir()
    write_eml(legacy_source / "legitimate.eml", subject="Routine", body="Different message")
    write_eml(individual_source / "suspicious.eml", subject="Notice", body="Account action requested")
    manifest = make_manifest(tmp_path, {
        "sources": [{"path": "legacy", "label": "LEGITIMATE"}],
        "files": [{"path": "individual/suspicious.eml", "label": "SUSPICIOUS"}],
    })
    output = tmp_path / "out.csv"

    preprocess(manifest, output)

    with output.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert rows == [
        {"email_text": "Subject: Routine\n\nDifferent message", "label": "LEGITIMATE", "source_files": '["legacy/legitimate.eml"]'},
        {"email_text": "Subject: Notice\n\nAccount action requested", "label": "SUSPICIOUS", "source_files": '["individual/suspicious.eml"]'},
    ]


def test_excludes_empty_and_over_length_messages(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    write_eml(source / "empty.eml", subject="", body="")
    # Subject contributes to the extracted text, so set an oversized body instead.
    write_eml(source / "long.eml", subject="", body="x" * (MAX_CHARS + 1))
    manifest = make_manifest(tmp_path, {"sources": [{"path": "source", "label": "LEGITIMATE"}]})
    output = tmp_path / "out.csv"
    with pytest.raises(PreprocessError, match='"empty_excluded": 1') as error:
        preprocess(manifest, output)
    assert '"too_long_excluded": 1' in str(error.value)
    assert '"rows_written": 0' in str(error.value)
    assert not output.exists()


def test_csv_escaping_round_trips_commas_quotes_and_newlines(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    write_eml(source / "mail.eml", subject='Review, "urgent"', body="First line\nSecond line")
    manifest = make_manifest(tmp_path, {"sources": [{"path": "source", "label": "PHISHING"}]})
    output = tmp_path / "out.csv"
    preprocess(manifest, output)
    with output.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert rows[0] == {
        "email_text": 'Subject: Review, "urgent"\n\nFirst line\nSecond line',
        "label": "PHISHING",
        "source_files": '["source/mail.eml"]',
    }
    assert output.read_bytes().startswith(b"email_text,label,source_files\r\n")


def test_missing_explicit_manifest_label_is_rejected(tmp_path):
    manifest = make_manifest(tmp_path, {"sources": [{"path": "source"}]})
    with pytest.raises(PreprocessError, match="explicitly supply"):
        preprocess(manifest, tmp_path / "out.csv")


def test_per_file_manifest_assigns_explicit_labels(tmp_path):
    source = tmp_path / "messages"
    source.mkdir()
    write_eml(source / "one.eml", subject="One", body="First")
    write_eml(source / "two.eml", subject="Two", body="Second")
    manifest = make_manifest(tmp_path, {"files": [
        {"path": "messages/one.eml", "label": "PHISHING"},
        {"path": "messages/two.eml", "label": "legitimate"},
    ]})
    output = tmp_path / "out.csv"
    preprocess(manifest, output)
    with output.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert rows == [
        {"email_text": "Subject: One\n\nFirst", "label": "PHISHING", "source_files": '["messages/one.eml"]'},
        {"email_text": "Subject: Two\n\nSecond", "label": "LEGITIMATE", "source_files": '["messages/two.eml"]'},
    ]


@pytest.mark.parametrize("entry", [
    {"path": "messages/one.eml", "label": "SPAM"},
    {"path": "messages/one.txt", "label": "PHISHING"},
    {"path": "messages/missing.eml", "label": "PHISHING"},
])
def test_per_file_manifest_rejects_invalid_label_extension_or_missing_file(tmp_path, entry):
    source = tmp_path / "messages"
    source.mkdir()
    write_eml(source / "one.eml")
    manifest = make_manifest(tmp_path, {"files": [entry]})
    with pytest.raises(PreprocessError):
        preprocess(manifest, tmp_path / "out.csv")


def test_per_file_manifest_rejects_absolute_path(tmp_path):
    email_path = tmp_path / "one.eml"
    write_eml(email_path)
    manifest = make_manifest(tmp_path, {"files": [{"path": str(email_path), "label": "PHISHING"}]})
    with pytest.raises(PreprocessError, match="relative .eml"):
        preprocess(manifest, tmp_path / "out.csv")


def test_conflicting_labels_for_same_file_are_rejected(tmp_path):
    source = tmp_path / "messages"
    source.mkdir()
    write_eml(source / "one.eml")
    manifest = make_manifest(tmp_path, {
        "sources": [{"path": "messages", "label": "PHISHING"}],
        "files": [{"path": "messages/one.eml", "label": "LEGITIMATE"}],
    })
    with pytest.raises(PreprocessError, match="Conflicting labels"):
        preprocess(manifest, tmp_path / "out.csv")
