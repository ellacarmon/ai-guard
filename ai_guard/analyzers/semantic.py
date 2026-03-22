from __future__ import annotations

import os
from enum import Enum
from typing import Optional

import openai
from pydantic import BaseModel, Field

from ..models.schema import Finding


class SemanticDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


class SemanticVerdict(BaseModel):
    decision: SemanticDecision
    confidence_score: float = Field(ge=0.0, le=1.0)
    explanation: str
    flagged_pattern: str


class SemanticAnalyzerConfigError(Exception):
    """Raised when required Azure AI Foundry environment variables are not set."""


SYSTEM_PROMPT = (
    "You are a security analyst evaluating code snippets from AI agent tools. "
    "Your task is to determine whether a flagged code pattern represents a legitimate "
    "use of system-level APIs (e.g., a local math calculation using subprocess, a benign "
    "network request to a known service) or a genuinely malicious pattern (e.g., a reverse "
    "shell, data exfiltration, command injection). "
    "Consider the full context: file path, line number, category, and the code snippet itself. "
    "Return a structured verdict with your decision (allow or block), a confidence score "
    "between 0.0 and 1.0, a concise explanation of your reasoning, and the specific pattern "
    "that drove your decision."
)


class SemanticAnalyzer:
    def __init__(self, model: str = "gpt-4o-mini", confidence_threshold: float = 0.85):
        api_key = os.environ.get("AZURE_OPENAI_API_KEY")
        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
        api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")
        missing = [k for k, v in {
            "AZURE_OPENAI_API_KEY": api_key,
            "AZURE_OPENAI_ENDPOINT": endpoint,
        }.items() if not v]
        if missing:
            raise SemanticAnalyzerConfigError(
                f"Missing required environment variable(s): {', '.join(missing)}. "
                "Please set them before using the SemanticAnalyzer."
            )
        self.model = model
        self.confidence_threshold = confidence_threshold
        self.client = openai.AzureOpenAI(
            api_key=api_key,
            azure_endpoint=endpoint,
            api_version=api_version,
        )

    def analyze_snippet(self, finding: Finding) -> Optional[SemanticVerdict]:
        try:
            if finding.evidence:
                user_prompt = (
                    f"File: {finding.file_path}\n"
                    f"Line: {finding.line_number}\n"
                    f"Category: {finding.category.value}\n"
                    f"Code snippet:\n{finding.evidence}"
                )
            else:
                user_prompt = (
                    f"File: {finding.file_path}\n"
                    f"Line: {finding.line_number}\n"
                    f"Category: {finding.category.value}"
                )

            response = self.client.beta.chat.completions.parse(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                response_format=SemanticVerdict,
            )
            return response.choices[0].message.parsed
        except Exception:
            return None
