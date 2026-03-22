from __future__ import annotations

import sys
from typing import Callable, Dict, List, Optional

from ..models.schema import Category, Finding, Severity
from ..analyzers.semantic import SemanticAnalyzer, SemanticDecision
from .scoring import ScoringEngine

TRIGGER_CATEGORIES = {Category.CODE_EXECUTION, Category.NETWORK_ACCESS}

SEMANTIC_SAMPLE_SIZE = 3

SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


def select_top_trigger_findings(
    findings: List[Finding], *, limit: int = SEMANTIC_SAMPLE_SIZE
) -> List[Finding]:
    """Return up to `limit` code_execution / network_access findings for the LLM.

    Selection policy (deterministic, no ML here):

    1. **Eligible** — only ``code_execution`` and ``network_access`` (same gate as before).

    2. **Sort** — descending by static ``severity`` (CRITICAL→LOW), then by
       ``confidence``. This is the primary "how dangerous" ordering.

    3. **De-duplicate by (rule_id, file_path)** — walk the sorted list and keep
       the first occurrence per pair. That instance is already the strongest hit
       for that rule in that file. This spreads samples across *files* and *rules*
       without letting thousands of identical repeats crowd out other locations.

    4. **Take the first ``limit`` representatives**. If there are fewer than
       ``limit`` unique pairs, **fill** from the full sorted list (next hits,
       including extra lines for the same rule/file) until ``limit`` or exhausted.

    Earlier we biased by "one finding per rule_id" globally, which could rank a
    lower-severity rule above a second CRITICAL hit for another file — this order
    fixes that.
    """
    trigger_findings = [f for f in findings if f.category in TRIGGER_CATEGORIES]
    if not trigger_findings:
        return []
    trigger_findings.sort(
        key=lambda f: (SEVERITY_RANK[f.severity], f.confidence), reverse=True
    )
    seen_pair: set[tuple[str, str]] = set()
    representatives: List[Finding] = []
    for f in trigger_findings:
        key = (f.rule_id, f.file_path)
        if key in seen_pair:
            continue
        seen_pair.add(key)
        representatives.append(f)

    picked = representatives[:limit]
    if len(picked) >= limit:
        return picked

    for f in trigger_findings:
        if len(picked) >= limit:
            break
        if f in picked:
            continue
        picked.append(f)
    return picked


def select_primary_finding(findings: List[Finding]) -> Optional[Finding]:
    """Return the single highest-priority trigger-category finding, or None."""
    batch = select_top_trigger_findings(findings, limit=1)
    return batch[0] if batch else None


class HybridEngine:
    def __init__(self, semantic_analyzer: SemanticAnalyzer):
        self.semantic_analyzer = semantic_analyzer

    def run(
        self,
        findings: List[Finding],
        context: Dict,
        config_path: Optional[str] = None,
        policy_path: Optional[str] = None,
        debug_log: Optional[Callable[[str], None]] = None,
    ) -> Dict:
        # Step 1: Static scoring
        scoring_engine = ScoringEngine(config_path=config_path, policy_path=policy_path)
        result = scoring_engine.calculate(findings, context)

        # Step 2: Gate — if static decision is allow, skip LLM
        if result["decision"].lower() == "allow":
            return result

        # Step 3: Gate — if no trigger-category finding, skip LLM
        semantic_sample = select_top_trigger_findings(findings)
        if not semantic_sample:
            return result

        if debug_log is not None:
            parts = [
                f"{f.file_path}:{f.line_number or '?'}"
                f" rule={f.rule_id} sev={f.severity.value}"
                for f in semantic_sample
            ]
            debug_log(
                "semantic LLM sample: "
                f"{len(semantic_sample)} finding(s) → " + " | ".join(parts)
            )

        # Step 4: LLM semantic analysis (batched top patterns for cross-context intent)
        verdict = self.semantic_analyzer.analyze_snippets(semantic_sample)

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
