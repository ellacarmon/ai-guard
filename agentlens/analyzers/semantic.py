from __future__ import annotations

import os
from enum import Enum
from typing import List, Optional

import openai
from pydantic import BaseModel, Field

from ..models.schema import Finding, Report


class SemanticDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


class SemanticVerdict(BaseModel):
    decision: SemanticDecision
    confidence_score: float = Field(ge=0.0, le=1.0)
    explanation: str
    flagged_pattern: str
    decoded_malicious_payload: bool = False


class SemanticAnalyzerConfigError(Exception):
    """Raised when required Azure AI Foundry environment variables are not set."""


SYSTEM_PROMPT = (
    "You are a security analyst evaluating code snippets from AI agent tools. "
    "You may receive one or several sampled findings from the same repository scan — "
    "they are the highest-severity static hits (often different rules or locations). "
    "Your task is to determine whether these patterns together suggest legitimate "
    "use of system-level APIs (e.g., local tooling, tests, sandboxed plugins) or a "
    "genuinely malicious posture (e.g., reverse shells, exfiltration, command injection). "
    "Use all samples to infer overall intent; do not judge a single line in isolation. "
    "Identify any Base64-encoded strings in the snippets. Speculatively decode them during analysis, "
    "even if the payload is partially obfuscated or embedded inside an import statement, exec(), or eval(). "
    "If the decoded content attempts to access sensitive environment variables such as os.environ, "
    "AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, TELEGRAM_TOKEN, API keys, or tokens, or attempts to establish "
    "unauthorized network access such as requests.post, urllib requests, socket usage, or similar exfiltration "
    "behavior, you must return decision=block, confidence_score=1.0, and set decoded_malicious_payload=true. "
    "Many legitimate Node.js libraries (like CLI wrappers or shell utilities) heavily use child_process and Buffer. "
    "Do NOT block simply because shell execution and buffers are present. You MUST find evidence of malicious intent "
    "such as decoding a hidden payload, exfiltrating process.env secrets to a network socket, or bypassing sandboxes. "
    "If the code appears to be a legitimate utility wrapping OS commands, return ALLOW. "
    "Return a structured verdict with your decision (allow or block), a confidence score "
    "between 0.0 and 1.0, a concise explanation referencing the combined evidence, and "
    "the specific pattern(s) that drove your decision (comma-separated if several)."
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

    @staticmethod
    def _finding_block(finding: Finding, index: int) -> str:
        lines = [
            f"--- Finding {index} ---",
            f"File: {finding.file_path}",
            f"Line: {finding.line_number}",
            f"Rule: {finding.rule_id}",
            f"Category: {finding.category.value}",
            f"Severity: {finding.severity.value}",
        ]
        if finding.evidence:
            lines.append(f"Code snippet:\n{finding.evidence}")
        return "\n".join(lines)

    def analyze_snippets(self, findings: List[Finding]) -> Optional[SemanticVerdict]:
        if not findings:
            return None
        try:
            blocks = [self._finding_block(f, i + 1) for i, f in enumerate(findings)]
            user_prompt = (
                f"The static analyzer sampled {len(findings)} high-priority finding(s). "
                "Evaluate them together.\n\n" + "\n\n".join(blocks)
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

    def analyze_snippet(self, finding: Finding) -> Optional[SemanticVerdict]:
        return self.analyze_snippets([finding])


Report.model_rebuild(_types_namespace={"SemanticVerdict": SemanticVerdict})
