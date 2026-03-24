from __future__ import annotations

import hashlib
import re
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Tuple

from ..analyzers.guardrail import GUARDRAIL_OVERRIDE_EXPLANATION
from ..models.schema import (
    Category,
    Finding,
    SemanticSampleItem,
    SemanticSampleSummary,
    Severity,
)
from ..analyzers.semantic import (
    SemanticAnalyzer,
    SemanticDecision,
    SemanticVerdict,
)
from .scoring import ScoringEngine

if TYPE_CHECKING:
    from ..analyzers.injection_prefilter import PromptInjectionPrefilter

TRIGGER_CATEGORIES = {Category.CODE_EXECUTION, Category.NETWORK_ACCESS}

SEMANTIC_SAMPLE_SIZE = 3
"""Max findings sent to the Azure semantic LLM per scan."""

SEMANTIC_CANDIDATE_POOL_SIZE = 15
"""How many top static trigger findings to score with the injection classifier before picking the batch."""

LOCAL_INJECTION_BLOCK_THRESHOLD = 0.90
"""If any local prompt-injection score meets this threshold, skip the cloud LLM and block."""

OBFUSCATION_RULE_IDS = {
    "CODE_OBFUSCATION_DETECTED",
    "SKILL_OBFUSCATED_CODE",
    "SC3",
}

SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


@dataclass(frozen=True)
class SemanticSelection:
    findings: List[Finding]
    injection_scores: List[Optional[float]]
    prefilter_model: Optional[str]
    candidate_pool_count: int
    hard_block_verdict: Optional[SemanticVerdict] = None

    def __iter__(self):
        yield self.findings
        yield self.injection_scores
        yield self.prefilter_model


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


def finding_text_for_injection_classifier(finding: Finding) -> str:
    """Text passed to the local injection model (description + evidence, truncated)."""
    parts = [finding.description or "", finding.evidence or ""]
    text = "\n".join(p for p in parts if p).strip()
    if not text:
        text = finding.file_path or " "
    return text[:4000]


def normalize_injection_text(text: str) -> str:
    """Normalize snippet text so repeated injected instructions cluster together."""
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[\"'`]+", "", text)
    return text.strip()[:1200]


def finding_cluster_key(finding: Finding) -> str:
    text = normalize_injection_text(finding_text_for_injection_classifier(finding))
    if not text:
        text = finding.file_path or finding.rule_id
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return f"{finding.rule_id}:{digest}"


def choose_representative(
    current: Tuple[Finding, float],
    candidate: Tuple[Finding, float],
) -> Tuple[Finding, float]:
    cur_finding, cur_score = current
    cand_finding, cand_score = candidate
    cur_key = (cur_score, SEVERITY_RANK[cur_finding.severity], cur_finding.confidence)
    cand_key = (
        cand_score,
        SEVERITY_RANK[cand_finding.severity],
        cand_finding.confidence,
    )
    return candidate if cand_key > cur_key else current


def select_findings_for_semantic_llm(
    findings: List[Finding],
    *,
    prefilter: Optional["PromptInjectionPrefilter"] = None,
    sample_size: int = SEMANTIC_SAMPLE_SIZE,
    pool_size: int = SEMANTIC_CANDIDATE_POOL_SIZE,
) -> SemanticSelection:
    """Pick findings for the semantic LLM; optionally rank a larger pool by injection score.

    Without ``prefilter``, behavior matches the historical policy: top ``sample_size``
    trigger findings by static severity/confidence (pool size only affects work done).

    With ``prefilter``, all trigger findings are scored locally, clustered by normalized
    snippet content, and only the strongest representative from each cluster competes for
    the limited semantic LLM budget. Extremely high-confidence injection scores block
    immediately and skip the cloud LLM.
    """
    pool = select_top_trigger_findings(findings, limit=pool_size)
    if not pool:
        return SemanticSelection([], [], None, 0)

    if prefilter is None:
        chosen = pool[:sample_size]
        scores: List[Optional[float]] = [None] * len(chosen)
        return SemanticSelection(chosen, scores, None, len(pool))

    try:
        trigger_findings = [f for f in findings if f.category in TRIGGER_CATEGORIES]
        texts = [finding_text_for_injection_classifier(f) for f in trigger_findings]
        raw_scores = prefilter.score_texts(texts)
    except Exception as e:
        print(
            f"WARNING: Injection prefilter failed ({e}); using static order for semantic batch.",
            file=sys.stderr,
        )
        chosen = pool[:sample_size]
        return SemanticSelection(chosen, [None] * len(chosen), None, len(pool))

    model_id = getattr(prefilter, "model_id", None)
    scored = list(zip(trigger_findings, raw_scores))
    hard_block = max(
        scored,
        key=lambda p: (p[1], SEVERITY_RANK[p[0].severity], p[0].confidence),
        default=None,
    )
    if hard_block is not None and hard_block[1] > LOCAL_INJECTION_BLOCK_THRESHOLD:
        finding, score = hard_block
        return SemanticSelection(
            [],
            [],
            model_id,
            len(scored),
            hard_block_verdict=SemanticVerdict(
                decision=SemanticDecision.BLOCK,
                confidence_score=1.0,
                explanation=GUARDRAIL_OVERRIDE_EXPLANATION,
                flagged_pattern=(
                    f"local_prompt_injection_guardrail(score={score:.2f},"
                    f" file={finding.file_path}:{finding.line_number or '?'})"
                ),
            ),
        )

    representatives: Dict[str, Tuple[Finding, float]] = {}
    for finding, score in scored:
        key = finding_cluster_key(finding)
        current = representatives.get(key)
        candidate = (finding, score)
        representatives[key] = candidate if current is None else choose_representative(current, candidate)

    paired = list(representatives.values())
    paired.sort(
        key=lambda p: (-p[1], SEVERITY_RANK[p[0].severity], p[0].confidence),
    )
    top = paired[:sample_size]
    return SemanticSelection(
        [p[0] for p in top],
        [p[1] for p in top],
        model_id,
        len(representatives),
    )


def build_semantic_sample_summary(
    trigger_findings: List[Finding],
    sample: List[Finding],
    *,
    candidate_pool_count: int = 0,
    prefilter_model: Optional[str] = None,
    injection_scores: Optional[List[Optional[float]]] = None,
) -> SemanticSampleSummary:
    """Counts eligible trigger findings vs. the batch sent to the semantic analyzer."""
    inj = injection_scores or [None] * len(sample)
    return SemanticSampleSummary(
        trigger_finding_count=len(trigger_findings),
        candidate_pool_count=candidate_pool_count,
        prefilter_model=prefilter_model,
        sent_finding_count=len(sample),
        sample_limit=SEMANTIC_SAMPLE_SIZE,
        unique_file_count=len({f.file_path for f in sample}),
        items=[
            SemanticSampleItem(
                file_path=f.file_path,
                line_number=f.line_number,
                rule_id=f.rule_id,
                severity=f.severity,
                category=f.category,
                injection_score=inj[i] if i < len(inj) else None,
            )
            for i, f in enumerate(sample)
        ],
    )


def select_primary_finding(findings: List[Finding]) -> Optional[Finding]:
    """Return the single highest-priority trigger-category finding, or None."""
    batch = select_top_trigger_findings(findings, limit=1)
    return batch[0] if batch else None


class HybridEngine:
    def __init__(
        self,
        semantic_analyzer: SemanticAnalyzer,
        injection_prefilter: Optional["PromptInjectionPrefilter"] = None,
    ):
        self.semantic_analyzer = semantic_analyzer
        self.injection_prefilter = injection_prefilter

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
        trigger_findings = [f for f in findings if f.category in TRIGGER_CATEGORIES]
        selection = select_findings_for_semantic_llm(
            findings,
            prefilter=self.injection_prefilter,
            sample_size=SEMANTIC_SAMPLE_SIZE,
            pool_size=SEMANTIC_CANDIDATE_POOL_SIZE,
        )
        sample_summary = build_semantic_sample_summary(
            trigger_findings,
            selection.findings,
            candidate_pool_count=selection.candidate_pool_count,
            prefilter_model=selection.prefilter_model,
            injection_scores=selection.injection_scores,
        )

        if selection.hard_block_verdict is not None:
            result["decision"] = "block"
            result["confidence"] = 1.0
            result["explanation"] = GUARDRAIL_OVERRIDE_EXPLANATION
            result["semantic_verdict"] = selection.hard_block_verdict
            result["semantic_sample"] = sample_summary
            return result

        semantic_sample = selection.findings
        inj_scores = selection.injection_scores
        if not semantic_sample:
            result["semantic_sample"] = sample_summary
            return result

        if debug_log is not None:
            parts = []
            for f, s in zip(semantic_sample, inj_scores):
                extra = f" inj={s:.3f}" if s is not None else ""
                parts.append(
                    f"{f.file_path}:{f.line_number or '?'}"
                    f" rule={f.rule_id} sev={f.severity.value}{extra}"
                )
            debug_log(
                "semantic LLM sample: "
                f"{len(semantic_sample)} finding(s) → " + " | ".join(parts)
            )

        # Step 4: LLM semantic analysis (batched top patterns for cross-context intent)
        verdict = self.semantic_analyzer.analyze_snippets(semantic_sample)

        # Step 5: Handle None verdict (LLM failure)
        if verdict is None:
            print("WARNING: SemanticAnalyzer returned None; using static result.", file=sys.stderr)
            result["semantic_sample"] = sample_summary
            return result

        # Step 6: Apply override logic
        if verdict.explanation == GUARDRAIL_OVERRIDE_EXPLANATION:
            result["decision"] = "block"
            result["confidence"] = 1.0
            result["explanation"] = GUARDRAIL_OVERRIDE_EXPLANATION
            result["semantic_verdict"] = verdict
            result["semantic_sample"] = sample_summary
            return result

        obfuscation_triggered = any(f.rule_id in OBFUSCATION_RULE_IDS for f in findings)
        decoded_payload_confirmed = (
            obfuscation_triggered
            and verdict.decision == SemanticDecision.BLOCK
            and verdict.decoded_malicious_payload
        )

        if decoded_payload_confirmed:
            result["decision"] = "block"
            result["confidence"] = 1.0
            result["explanation"] = (
                "[Critical] Malicious obfuscated payload detected and decoded. "
                + verdict.explanation
                + " | "
                + result.get("explanation", "")
            )
            result["semantic_verdict"] = verdict
            result["semantic_sample"] = sample_summary
            return result

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

        # Step 7: Attach verdict and sample stats (eligible vs. sent, paths)
        result["semantic_verdict"] = verdict
        result["semantic_sample"] = sample_summary

        return result
