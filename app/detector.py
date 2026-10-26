import json

from pydantic import ValidationError

from .ollama_client import (
    OllamaError,
    generate_response,
)
from .prompts import PHISHING_DETECTION_PROMPT
from .schemas import DetectResponse


class DetectionError(Exception):
    """Raised when classification cannot be completed."""


def _inconclusive_response() -> DetectResponse:
    return DetectResponse(
        classification="INCONCLUSIVE",
        risk_level="UNKNOWN",
        indicators=[],
        explanation="The message could not be classified reliably from the available analysis.",
        recommended_action="Verify the message through a trusted channel before acting.",
    )


def classify_message(email_text: str) -> DetectResponse:
    """Classify an email using a local LLM."""

    if not email_text.strip():
        raise ValueError("Email text cannot be empty.")

    # JSON serialization keeps arbitrary email content inside one data value;
    # email text cannot close a prompt delimiter or add a sibling field.
    email_json = json.dumps({"email_text": email_text}, ensure_ascii=False)
    prompt = PHISHING_DETECTION_PROMPT.format(email_json=email_json)
    try:
        raw_result = generate_response(prompt)
    except OllamaError as exc:
        raise DetectionError(
            "The local classification model is unavailable."
        ) from exc

    try:
        parsed_result = json.loads(raw_result)
        return DetectResponse.model_validate(parsed_result)
    except (json.JSONDecodeError, TypeError, ValidationError):
        return _inconclusive_response()
