from email.message import EmailMessage

from scripts.inspect_eml_links import inspect_eml, inspect_html_links, render_report


def test_html_encoded_href_preserves_original_and_decoded_values():
    result = inspect_html_links('<a href="https://actual.example/path?a=1&amp;b=2">https://display.example/login</a>')

    link = result["links"][0]
    assert link["visible_text"] == "https://display.example/login"
    assert link["href_original_attribute_value"] == "https://actual.example/path?a=1&amp;b=2"
    assert link["href_html_decoded_value"] == "https://actual.example/path?a=1&b=2"
    assert "visible_url_hostname_differs_from_href_hostname" in link["indicators"]


def test_missing_href_is_recorded_without_inventing_a_destination():
    result = inspect_html_links("<a>Continue</a>")
    link = result["links"][0]

    assert link["visible_text"] == "Continue"
    assert link["href_attribute_present"] is False
    assert link["href_original_attribute_value"] is None
    assert link["href_html_decoded_value"] is None
    assert link["indicators"] == ["anchor_has_no_href"]


def test_malformed_html_is_parsed_statically_and_flags_ip_host():
    result = inspect_html_links("<html><a href='http://192.0.2.4/login'>Sign in")
    link = result["links"][0]

    assert result["parse_warning"] is None
    assert link["visible_text"] == "Sign in"
    assert link["hostname"] == "192.0.2.4"
    assert "ip_address_hostname" in link["indicators"]


def test_untrusted_markup_script_and_markdown_text_remain_inert_in_report():
    html = (
        '<a href="https://safe.example">Click &lt;/email&gt; # reviewer instruction ```</a>'
        '<script><a href="https://ignored.example">not parsed</a></script>'
    )
    inspected = inspect_html_links(html)
    result = {
        "source_file": "datasets/raw/example.eml",
        "source_sha256": "abc123",
        "subject": "Test",
        "html_parts": [{"mime_part_number": 1, **inspected}],
        "link_count": len(inspected["links"]),
    }
    report = render_report([result])

    assert len(inspected["links"]) == 1
    assert "https://ignored.example" not in report
    assert "&lt;/email&gt;" in report
    assert "&lt;script&gt;" not in report
    assert "reviewer instruction" in report
    assert "````text" in report


def test_eml_inspection_reads_html_part_and_skips_attachment(tmp_path):
    message = EmailMessage()
    message["Subject"] = "Static test"
    message.set_content("Plain content")
    message.add_alternative('<a href="https://example.test/?x=1&amp;y=2">Example</a>', subtype="html")
    message.add_attachment(b"<a href='https://attachment.example'>Do not parse attachment</a>", maintype="text", subtype="html", filename="file.html")
    source = tmp_path / "message.eml"
    source.write_bytes(message.as_bytes())

    result = inspect_eml(source, tmp_path)

    assert result["source_file"] == "message.eml"
    assert result["link_count"] == 1
    link = result["html_parts"][0]["links"][0]
    assert link["visible_text"] == "Example"
    assert link["href_original_attribute_value"] == "https://example.test/?x=1&amp;y=2"
