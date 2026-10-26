import hashlib
import ipaddress
import json
import os
import warnings
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

from .prompts import PHISHING_DETECTION_PROMPT

load_dotenv()

OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://localhost:11434",
).rstrip("/")

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5:3b",
)
OLLAMA_GENERATION_OPTIONS = {"temperature": 0}
OLLAMA_STREAM = False
OLLAMA_REQUEST_TIMEOUT = (5, 180)
OLLAMA_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "classification": {"type": "string", "enum": ["PHISHING", "LEGITIMATE", "SUSPICIOUS", "INCONCLUSIVE"]},
        "risk_level": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "UNKNOWN"]},
        "indicators": {"type": "array", "items": {"type": "string"}},
        "explanation": {"type": "string"},
        "recommended_action": {"type": "string"},
    },
    "required": ["classification", "risk_level", "indicators", "explanation", "recommended_action"],
    "additionalProperties": False,
}


def _is_loopback_endpoint(endpoint: str) -> bool:
    try:
        hostname = urlparse(endpoint).hostname
        if not hostname:
            return False
        normalized = hostname.rstrip(".").lower()
        if normalized == "localhost" or normalized.endswith(".localhost"):
            return True
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def inference_metadata() -> dict[str, object]:
    """Return non-sensitive inference configuration for reproducible evaluation."""
    return {
        "model_tag": OLLAMA_MODEL,
        "prompt_sha256": hashlib.sha256(PHISHING_DETECTION_PROMPT.encode("utf-8")).hexdigest(),
        "generation_settings": {
            "stream": OLLAMA_STREAM,
            "options": dict(OLLAMA_GENERATION_OPTIONS),
            "format": "json_schema",
            "format_schema_sha256": hashlib.sha256(
                json.dumps(OLLAMA_RESPONSE_SCHEMA, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "request_timeout_seconds": {"connect": OLLAMA_REQUEST_TIMEOUT[0], "read": OLLAMA_REQUEST_TIMEOUT[1]},
        },
    }


if not _is_loopback_endpoint(OLLAMA_BASE_URL):
    warnings.warn(
        "OLLAMA_BASE_URL is configured for a non-loopback endpoint; submitted email text will be sent to that remote service.",
        RuntimeWarning,
        stacklevel=2,
    )


class OllamaError(Exception):
    """Raised when local model inference fails."""


def generate_response(prompt: str, response_schema: dict | None = None) -> str:
    """Send a prompt to the locally running Ollama model."""

    url = f"{OLLAMA_BASE_URL}/api/generate"

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": OLLAMA_STREAM,
        "format": response_schema or OLLAMA_RESPONSE_SCHEMA,
        "options": OLLAMA_GENERATION_OPTIONS,
    }

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=OLLAMA_REQUEST_TIMEOUT,
        )

        response.raise_for_status()

        data = response.json()
        result = data.get("response")

        if not isinstance(result, str) or not result.strip():
            raise OllamaError("Ollama returned an empty response.")

        return result

    except requests.RequestException as exc:
        raise OllamaError(
            "Could not obtain a response from the local Ollama service."
        ) from exc
