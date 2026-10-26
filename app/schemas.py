from typing import Literal

from pydantic import BaseModel, Field, model_validator


Classification = Literal[
    "PHISHING",
    "LEGITIMATE",
    "SUSPICIOUS",
    "INCONCLUSIVE",
]

RiskLevel = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
    "UNKNOWN",
]


class DetectRequest(BaseModel):
    email_text: str = Field(
        ...,
        min_length=1,
        max_length=20_000,
        description="Email text to analyze",
    )


class DetectResponse(BaseModel):
    classification: Classification
    risk_level: RiskLevel

    indicators: list[str] = Field(default_factory=list)

    explanation: str
    recommended_action: str

    @model_validator(mode="after")
    def validate_classification_risk_pair(self):
        is_inconclusive = self.classification == "INCONCLUSIVE"
        has_unknown_risk = self.risk_level == "UNKNOWN"
        if is_inconclusive != has_unknown_risk:
            raise ValueError(
                "INCONCLUSIVE must use UNKNOWN risk, and other classifications must use a known risk level."
            )
        has_observed_indicators = any(indicator.strip() for indicator in self.indicators)
        if self.classification in {"PHISHING", "SUSPICIOUS"} and not has_observed_indicators:
            raise ValueError("PHISHING and SUSPICIOUS responses must include observed evidence.")
        if self.risk_level == "HIGH" and not has_observed_indicators:
            raise ValueError("HIGH risk responses must include an observed indicator for the serious action.")
        if not self.explanation.strip() or not self.recommended_action.strip():
            raise ValueError("Explanation and recommended action must not be empty.")
        return self
