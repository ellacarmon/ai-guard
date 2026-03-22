from __future__ import annotations

import sys
from typing import Dict, List, Optional

from ..models.schema import Category, Finding, Severity
from ..analyzers.semantic import SemanticAnalyzer, SemanticDecision
from .scoring import ScoringEngine

TRIGGER_CATEGORIES = {Category.CODE_EXECUTION, Category.NETWORK_ACCESS}

SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


def select_primary_finding(findings: List[Finding]) -> Optional[Finding]:
    """Return the highest-priority trigger-category finding, or None."""
    trigger_findings = [f for f in findings if f.category in TRIGGER_CATEGORIES]
    if not trigger_findings:
        return None
    return max(trigger_findings, key=lambda f: (SEVERITY_RANK[f.severity], f.confidence))


class HybridEngine:
    def __init__(self, semantic_analyzer: SemanticAnalyzer):
        self.semantic_analyzer = semantic_analyzer

    def run(
        self,
        findings: List[Finding],
        context: Dict,
        config_path: Optional[str] = None,
        policy_path: Optional[str] = None,
    ) -> Dict:
        # Step 1: Static scoring
        scoring_engine = ScoringEngine(config_path=config_path, policy_path=policy_path)
        result = scoring_engine.calculate(findings, context)

        # Step 2: Gate — if static decision is allow, skip LLM
        if result["decision"].lower() == "allow":
            return result

        # Step 3: Gate — if no trigger-category finding, skip LLM
        primary_finding = select_primary_finding(findings)
        if primary_finding is None:
            return result

        # Step 4: LLM semantic analysis
        verdict = self.semantic_analyzer.analyze_snippet(primary_finding)

        # Step 5: Handle None verdict (LLM failure)
        if verdict is None:
            print("WARNING: SemanticAnalyzer returned None; using static result.", file=sys.stderr)
            return result

        # Step 6: Apply override logic
        if (
            verdict.decision == SemanticDecision.ALLOW
            and verdict.confidence_score >= self.semantic_analyzer.confidence_threshold
        ):
            result["decision"] = "allow"
            result["recommendation"] = "Safe to install — initial risks were semantically cleared."
            result["explanation"] = (
                "[Semantic Override] " + verdict.explanation + " | " + result.get("explanation", "")
            )
        else:
            result["explanation"] = (
                "[Semantic Analysis] " + verdict.explanation + " | " + result.get("explanation", "")
            )

        # Step 7: Attach verdict
        result["semantic_verdict"] = verdict

        return result
