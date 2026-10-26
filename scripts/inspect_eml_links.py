"""Statically inspect anchor hrefs in local .eml HTML parts without network access."""

from __future__ import annotations

import argparse
import hashlib
import html
import ipaddress
import json
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .preprocess_emails import PreprocessError, _decoded_text
except ImportError:  # Support direct execution from the project root.
    from preprocess_emails import PreprocessError, _decoded_text

URL_SHORTENERS = {
    "bit.ly", "buff.ly", "cutt.ly", "goo.gl", "is.gd", "lnkd.in", "ow.ly",
    "rebrand.ly", "t.co", "tiny.cc", "tinyurl.com", "shorturl.at",
}
_RAW_HREF = re.compile(r"(?is)\shref\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))")
_VISIBLE_URL = re.compile(r"(?i)(?:https?://|www\.)[^\s<>\"']+")
_VISIBLE_DOMAIN = re.compile(r"(?i)(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}(?![\w-])")


class LinkInspectionError(ValueError):
    """Raised for invalid local message inputs or report paths."""


class _AnchorParser(HTMLParser):
    """Collect anchor labels and raw href attributes; never interpret active content."""

    _NON_VISIBLE = {"script", "style", "template", "noscript"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[dict[str, Any]] = []
        self.active: list[dict[str, Any]] = []
        self.nonvisible_depth = 0
        self.parse_warning: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in self._NON_VISIBLE:
            self.nonvisible_depth += 1
        if tag != "a":
            return
        start_tag = self.get_starttag_text() or ""
        match = _RAW_HREF.search(start_tag)
        raw_value = next((value for value in match.groups() if value is not None), None) if match else None
        attr_present = any(name.lower() == "href" for name, _ in attrs)
        if attr_present and match is None:
            raw_value = None
        anchor = {"raw_href": raw_value, "href_present": attr_present, "visible_parts": []}
        self.active.append(anchor)
        self.anchors.append(anchor)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "a" and self.active:
            self.active.pop()
        if tag in self._NON_VISIBLE and self.nonvisible_depth:
            self.nonvisible_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.nonvisible_depth:
            return
        for anchor in self.active:
            anchor["visible_parts"].append(data)

    def close(self) -> None:
        try:
            super().close()
        except (AssertionError, ValueError) as exc:
            self.parse_warning = type(exc).__name__


def _url_parts(value: str) -> tuple[str | None, str | None]:
    candidate = value.strip()
    if not candidate:
        return None, None
    try:
        parsed = urlsplit(candidate)
        if not parsed.scheme and not candidate.startswith("//"):
            parsed = urlsplit("//" + candidate)
        return parsed.scheme.lower() or None, parsed.hostname
    except ValueError:
        return None, None


def _visible_hosts(text: str) -> list[str]:
    values = _VISIBLE_URL.findall(text)
    values.extend(_VISIBLE_DOMAIN.findall(text))
    hosts = []
    for value in values:
        candidate = value.rstrip(".,;:!?)}")
        _, host = _url_parts(candidate)
        if host:
            hosts.append(host.rstrip(".").lower())
    return list(dict.fromkeys(hosts))


def _inspect_href(raw_href: str | None, visible_text: str, href_present: bool) -> dict[str, Any]:
    decoded = html.unescape(raw_href) if raw_href is not None else None
    scheme, hostname = _url_parts(decoded or "")
    flags: list[str] = []
    if not href_present:
        flags.append("anchor_has_no_href")
    elif decoded == "":
        flags.append("empty_href_value")
    if decoded and scheme and scheme not in {"http", "https", "mailto", "tel"}:
        flags.append(f"non_http_or_mailto_scheme:{scheme}")
    if hostname:
        normalized_host = hostname.rstrip(".").lower()
        if any(ord(char) > 127 for char in hostname):
            flags.append("unicode_hostname")
        if any(label.lower().startswith("xn--") for label in hostname.split(".")):
            flags.append("punycode_hostname")
        try:
            ipaddress.ip_address(normalized_host)
        except ValueError:
            pass
        else:
            flags.append("ip_address_hostname")
        if normalized_host in URL_SHORTENERS:
            flags.append("known_url_shortener_hostname")
        labels = normalized_host.split(".")
        if normalized_host == "localhost" or normalized_host.endswith((".local", ".localhost")):
            flags.append("local_or_nonpublic_hostname_form")
        if len(labels) >= 6 or any(label.startswith("-") or label.endswith("-") or "_" in label for label in labels):
            flags.append("unusual_hostname_structure")
    if decoded:
        displayed_hosts = _visible_hosts(visible_text)
        actual_host = hostname.rstrip(".").lower() if hostname else None
        mismatches = [host for host in displayed_hosts if host != actual_host]
        if displayed_hosts and (not actual_host or mismatches):
            flags.append("visible_url_hostname_differs_from_href_hostname")
    return {
        "href_attribute_present": href_present,
        "href_original_attribute_value": raw_href,
        "href_html_decoded_value": decoded,
        "scheme": scheme,
        "hostname": hostname,
        "visible_text_hosts": _visible_hosts(visible_text),
        "indicators": flags,
        "indicator_limit": "Static investigation indicators only; none proves phishing or a malicious destination.",
    }


def inspect_html_links(html_text: str) -> dict[str, Any]:
    parser = _AnchorParser()
    try:
        parser.feed(html_text)
        parser.close()
    except (AssertionError, ValueError) as exc:
        parser.parse_warning = parser.parse_warning or type(exc).__name__
    links = []
    for anchor in parser.anchors:
        visible_text = re.sub(r"\s+", " ", "".join(anchor["visible_parts"])).strip()
        inspected = _inspect_href(anchor["raw_href"], visible_text, anchor["href_present"])
        links.append({"visible_text": visible_text, **inspected})
    return {"links": links, "parse_warning": parser.parse_warning}


def inspect_eml(path: str | Path, project_root: str | Path) -> dict[str, Any]:
    source = Path(path).resolve()
    root = Path(project_root).resolve()
    try:
        relative = source.relative_to(root).as_posix()
        raw = source.read_bytes()
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except (OSError, ValueError) as exc:
        raise LinkInspectionError(f"Could not read an .eml beneath the project root: {path}") from exc
    if source.suffix.lower() != ".eml":
        raise LinkInspectionError(f"Input is not an .eml file: {path}")

    html_parts = []
    for part_number, part in enumerate(message.walk(), start=1):
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type().lower() != "text/html":
            continue
        html_content = _decoded_text(part)
        result = inspect_html_links(html_content)
        html_parts.append({"mime_part_number": part_number, "content_type": "text/html", **result})

    return {
        "source_file": relative,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "subject": str(message.get("subject", "") or "").strip(),
        "html_parts": html_parts,
        "link_count": sum(len(part["links"]) for part in html_parts),
        "limitations": "Local static MIME/HTML parsing only. No DNS, redirects, requests, remote content, scripts, or attachments were accessed or executed.",
    }


def render_report(results: list[dict[str, Any]]) -> str:
    lines = [
        "# Static hyperlink evidence report (message-000013 through 000016)",
        "",
        "> Static inspection only. Email content and URL attributes are untrusted data. URLs below are literal text, not links to follow.",
        "> Hostname indicators are investigation leads only, not proof of phishing or maliciousness.",
        "",
        "## Method and limits",
        "",
        "MIME and HTML were parsed locally. Attachments were skipped. HTML entities in `href` attributes were decoded for comparison while original attribute values were retained. Visible link text was extracted as text. No DNS was resolved; no URL was opened, fetched, or redirected; no JavaScript or other active content ran.",
        "",
    ]
    for result in results:
        lines.extend([
            f"## {result['source_file']}",
            "",
            f"- **Subject:** {_fence(result['subject'] or '(absent)')}",
            f"- **Source SHA-256:** `{result['source_sha256']}`",
            f"- **HTML parts:** {len(result['html_parts'])}; **anchors found:** {result['link_count']}",
            "",
        ])
        if not result["html_parts"]:
            lines.extend(["No `text/html` MIME part was present.", ""])
        for part in result["html_parts"]:
            lines.extend([f"### HTML MIME part {part['mime_part_number']}", ""])
            if part["parse_warning"]:
                lines.extend([f"Parser note: `{part['parse_warning']}`", ""])
            if not part["links"]:
                lines.extend(["No anchor elements were found in this part.", ""])
            for number, link in enumerate(part["links"], start=1):
                lines.extend([
                    f"#### Link {number}",
                    "",
                    "**Visible text**",
                    "",
                    _fence(link["visible_text"] or "(empty)"),
                    "",
                    "**Original href attribute value**",
                    "",
                    _fence(link["href_original_attribute_value"] if link["href_original_attribute_value"] is not None else "(missing)"),
                    "",
                    "**HTML-decoded href value**",
                    "",
                    _fence(link["href_html_decoded_value"] if link["href_html_decoded_value"] is not None else "(missing)"),
                    "",
                    f"- **Parsed scheme:** `{link['scheme'] or '(none)'}`",
                    "- **Parsed hostname:**",
                    _fence(link["hostname"] or "(none)"),
                    "- **Visible URL-like hostnames:**",
                    _fence(", ".join(link["visible_text_hosts"]) or "(none)"),
                    "- **Static indicators:**",
                    _fence(", ".join(link["indicators"]) or "(none)"),
                    "",
                ])
    lines.extend([
        "## Interpretation limits",
        "",
        "A visible-text/href mismatch, unusual host form, Unicode or punycode hostname, IP address, or shortener can justify human investigation. None by itself establishes intent, ownership, destination behavior, or phishing. This report does not label emails.",
        "",
    ])
    return "\n".join(lines)


def _fence(value: str) -> str:
    escaped = html.escape(value, quote=True)
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", escaped)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{escaped}\n{fence}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="+", help="Local .eml paths to inspect")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--output", default="datasets/static_link_inspection_000013-000016.md")
    args = parser.parse_args()
    try:
        results = [inspect_eml(path, args.project_root) for path in args.sources]
    except LinkInspectionError as exc:
        parser.error(str(exc))
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_report(results), encoding="utf-8")
    print(json.dumps({"report": str(destination), "sources": len(results), "anchors": sum(r["link_count"] for r in results)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
