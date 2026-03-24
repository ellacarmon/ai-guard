import os
import yaml
from typing import Dict, List, Optional, Tuple, Union

from ..models.schema import (
    DecisionResult, DecisionVerdict, RiskLevel, Category, Finding,
    ExploitabilityResult, ExploitabilityLevel
)


class DecisionEngine:
    """
    Production-grade decision engine.

    Converts analysis results into allow / warn / block decisions using a
    multi-signal evaluation chain:

        combination_rules → category_overrides → score_threshold → risk_level_default

    With confidence-based downgrade applied as a final pass.
    """

    # Human-readable labels for risk categories
    CATEGORY_LABELS = {
        "code_execution": "code execution capability",
        "prompt_injection": "prompt injection signals",
        "supply_chain": "supply chain risk indicators",
        "filesystem_access": "filesystem access patterns",
        "network_access": "network access patterns",
    }

    COMPLEXITY_LABELS = {
        "critical": "critical-severity",
        "high": "high-severity",
        "low": "low-severity",
        "none": None,
    }

    SIGNAL_LABELS = {
        "strong": "strong",
        "medium": "moderate",
        "weak": "weak",
        "none": None,
    }

    def __init__(self, policy_path: Optional[str] = None):
        if policy_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            policy_path = os.path.join(base_dir, "rules", "decision_policy.yml")

        self.policy = self._load_policy(policy_path)

    # ------------------------------------------------------------------ #
    #  Policy loading
    # ------------------------------------------------------------------ #

    @staticmethod
    def _load_policy(path: str) -> Dict:
        """Load and validate the YAML policy file."""
        if not os.path.exists(path):
            return DecisionEngine._default_policy()

        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)

        return raw.get("decision", DecisionEngine._default_policy())

    @staticmethod
    def _default_policy() -> Dict:
        """Fallback policy when no file is provided."""
        return {
            "risk_levels": {"critical": 9.0, "high": 7.0, "medium": 4.0},
            "block_if": {
                "risk_score": 8.0,
                "categories": {},
                "combinations": [],
            },
            "warn_if": {"risk_score": 4.0, "categories": {}},
            "confidence": {
                "low_confidence_threshold": 0.5,
                "downgrade_on_low_confidence": True,
            },
            "recommendations": {
                "allow": "Safe to install — no significant risks detected.",
                "warn": "Install with caution — review flagged risks before use.",
                "block_high": "Manual review required — significant risks detected.",
                "block_critical": "Do not install — critical security risks detected.",
            },
        }

    # ------------------------------------------------------------------ #
    #  Public entry-point
    # ------------------------------------------------------------------ #

    def evaluate(
        self,
        risk_score: float,
        categories: Dict[str, float],
        features: Dict[str, Union[bool, int, str]],
        exploitability: Optional[ExploitabilityResult] = None,
        findings: Optional[List[Finding]] = None,
    ) -> DecisionResult:
        """
        Run the full decision pipeline and return a structured result.
        `exploitability` is optional; if not provided a default LOW result is used.
        """
        findings = findings or []

        # Default exploitability when not provided (e.g., in unit tests)
        if exploitability is None:
            exploitability = ExploitabilityResult(
                exploitability_score=0.0,
                exploitability_level=ExploitabilityLevel.LOW,
                is_exploitable=False,
                exposure_detected=False,
                attack_surface=[],
                attack_archetype=None,
                reasoning="No exploitability assessment provided.",
            )

        # 1. Map risk score → risk level
        risk_level = self._map_risk_level(risk_score)

        # 2. Compute confidence
        confidence = self._compute_confidence(findings, features, categories)

        # 3. Determine decision (multi-signal chain)
        decision, trigger_reason = self._determine_decision(
            risk_score, categories, risk_level, exploitability
        )

        # 4. Confidence-based downgrade
        decision = self._apply_confidence_downgrade(decision, confidence)

        # 5. Top contributing categories
        top_risks = self._top_risks(categories)

        # 6. Generate explanation
        explanation = self._generate_explanation(
            risk_level, decision, categories, features, trigger_reason,
        )

        # 7. Map recommendation
        recommendation = self._map_recommendation(decision, risk_level)

        return DecisionResult(
            risk_score=risk_score,
            risk_level=risk_level,
            decision=decision,
            confidence=round(confidence, 2),
            top_risks=top_risks,
            explanation=explanation,
            recommendation=recommendation,
            exploitability=exploitability,
        )

    # ------------------------------------------------------------------ #
    #  1. Risk level mapping
    # ------------------------------------------------------------------ #

    def _map_risk_level(self, score: float) -> RiskLevel:
        levels = self.policy.get("risk_levels", {})
        if score >= float(levels.get("critical", 9.0)):
            return RiskLevel.CRITICAL
        if score >= float(levels.get("high", 7.0)):
            return RiskLevel.HIGH
        if score >= float(levels.get("medium", 4.0)):
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    # ------------------------------------------------------------------ #
    #  2. Confidence computation
    # ------------------------------------------------------------------ #

    def _compute_confidence(
        self,
        findings: List[Finding],
        features: Dict[str, Union[bool, int, str]],
        categories: Dict[str, float],
    ) -> float:
        """
        Confidence is derived from three signals:
          - Mean finding confidence (0-1)
          - Coverage factor: how many files were analyzed (more files → higher)
          - Ambiguity penalty: ratio of weak/none signals in active categories
        """
        if not findings:
            return 1.0  # no findings = high confidence in "safe"

        # A) Mean finding confidence
        mean_conf = sum(getattr(f, "confidence", 1.0) for f in findings) / len(findings)

        # B) Coverage factor — diminishing returns on file count
        unique_files = features.get("unique_files_affected", 0)
        if isinstance(unique_files, bool):
            unique_files = 0
        coverage = min(1.0, unique_files / 5.0) if unique_files > 0 else 0.5

        # C) Ambiguity — count how many active categories have only weak signals
        active_cats = [c for c, s in categories.items() if s > 0]
        if active_cats:
            weak_count = 0
            for cat in active_cats:
                signal_key = self._signal_key_for_category(cat)
                signal = str(features.get(signal_key, "none"))
                if signal in ("weak", "none"):
                    weak_count += 1
            ambiguity_penalty = weak_count / len(active_cats)
        else:
            ambiguity_penalty = 0.0

        # Weighted combination
        confidence = (0.5 * mean_conf) + (0.2 * coverage) + (0.3 * (1.0 - ambiguity_penalty))
        return max(0.0, min(1.0, confidence))

    @staticmethod
    def _signal_key_for_category(cat: str) -> str:
        """Map category name to its signal feature key."""
        mapping = {
            "code_execution": "execution_signal",
            "prompt_injection": "injection_signal",
        }
        return mapping.get(cat, f"{cat}_signal")

    # ------------------------------------------------------------------ #
    #  3. Decision determination (multi-signal chain)
    # ------------------------------------------------------------------ #

    def _determine_decision(
        self,
        risk_score: float,
        categories: Dict[str, float],
        risk_level: RiskLevel,
        exploitability: ExploitabilityResult,
    ) -> Tuple[DecisionVerdict, str]:
        """
        Priority chain:
          0. Exploitability overrides → block
          1. Combination rules  → block
          2. Category overrides → block / warn
          3. Score thresholds   → block / warn
          4. Risk level default → allow
        Returns (decision, trigger_reason).
        """

        # --- 0. Exploitability Overrides ---
        if exploitability and exploitability.exploitability_level == ExploitabilityLevel.CRITICAL:
            has_exec = categories.get(Category.CODE_EXECUTION.value, 0.0) > 0 or categories.get("code_execution", 0.0) > 0
            has_inj = categories.get(Category.PROMPT_INJECTION.value, 0.0) > 0 or categories.get("prompt_injection", 0.0) > 0
            
            if has_exec and has_inj:
                return DecisionVerdict.BLOCK, "Critical exploitability: Prompt injection combined with execution capability"
            
            if has_exec and exploitability.exposure_detected:
                return DecisionVerdict.BLOCK, "Critical exploitability: Exposed unsafe execution pattern"

        # --- 1. Combination rules ---
        combo_result = self._check_combination_rules(categories)
        if combo_result is not None:
            return DecisionVerdict.BLOCK, combo_result

        # --- 2. Category overrides (block) ---
        block_cats = self.policy.get("block_if", {}).get("categories", {})
        for cat, threshold in block_cats.items():
            cat_score = categories.get(cat, 0.0)
            if cat_score >= float(threshold):
                label = self.CATEGORY_LABELS.get(cat, cat)
                return (
                    DecisionVerdict.BLOCK,
                    f"{label} score ({cat_score:.1f}) exceeds block threshold ({float(threshold):.1f})",
                )

        # --- 3. Score threshold (block) ---
        block_score = float(self.policy.get("block_if", {}).get("risk_score", 8.0))
        if risk_score >= block_score:
            return (
                DecisionVerdict.BLOCK,
                f"Overall risk score ({risk_score:.1f}) exceeds block threshold ({block_score:.1f})",
            )

        # --- 4. Category overrides (warn) ---
        warn_cats = self.policy.get("warn_if", {}).get("categories", {})
        for cat, threshold in warn_cats.items():
            cat_score = categories.get(cat, 0.0)
            if cat_score >= float(threshold):
                label = self.CATEGORY_LABELS.get(cat, cat)
                return (
                    DecisionVerdict.WARN,
                    f"{label} score ({cat_score:.1f}) exceeds warn threshold ({float(threshold):.1f})",
                )

        # --- 5. Score threshold (warn) ---
        warn_score = float(self.policy.get("warn_if", {}).get("risk_score", 4.0))
        if risk_score >= warn_score:
            return (
                DecisionVerdict.WARN,
                f"Overall risk score ({risk_score:.1f}) exceeds warn threshold ({warn_score:.1f})",
            )

        # --- 6. Default: allow ---
        return DecisionVerdict.ALLOW, "No thresholds exceeded"

    def _check_combination_rules(
        self, categories: Dict[str, float],
    ) -> Optional[str]:
        """
        Evaluate dangerous category combinations.
        Returns a trigger reason string if a rule fires, else None.
        """
        combinations = self.policy.get("block_if", {}).get("combinations", [])
        for rule in combinations:
            cats = rule.get("categories", [])
            min_scores = rule.get("min_scores", [])
            if len(cats) != len(min_scores):
                continue

            all_exceeded = True
            for cat, min_s in zip(cats, min_scores):
                if categories.get(cat, 0.0) < float(min_s):
                    all_exceeded = False
                    break

            if all_exceeded:
                return rule.get(
                    "reason",
                    f"Dangerous combination detected: {', '.join(cats)}",
                )
        return None

    # ------------------------------------------------------------------ #
    #  4. Confidence downgrade
    # ------------------------------------------------------------------ #

    def _apply_confidence_downgrade(
        self, decision: DecisionVerdict, confidence: float,
    ) -> DecisionVerdict:
        """Downgrade decisions when confidence is low."""
        conf_policy = self.policy.get("confidence", {})
        threshold = float(conf_policy.get("low_confidence_threshold", 0.5))
        should_downgrade = conf_policy.get("downgrade_on_low_confidence", True)

        if not should_downgrade or confidence >= threshold:
            return decision

        if decision == DecisionVerdict.BLOCK:
            return DecisionVerdict.WARN
        if decision == DecisionVerdict.WARN:
            return DecisionVerdict.ALLOW
        return decision

    # ------------------------------------------------------------------ #
    #  5. Top risks
    # ------------------------------------------------------------------ #

    @staticmethod
    def _top_risks(categories: Dict[str, float], top_n: int = 3) -> List[str]:
        """Return the top N contributing categories sorted by score."""
        active = [(c, s) for c, s in categories.items() if s > 0]
        active.sort(key=lambda x: x[1], reverse=True)
        return [c for c, _ in active[:top_n]]

    # ------------------------------------------------------------------ #
    #  6. Explanation generation
    # ------------------------------------------------------------------ #

    def _generate_explanation(
        self,
        risk_level: RiskLevel,
        decision: DecisionVerdict,
        categories: Dict[str, float],
        features: Dict[str, Union[bool, int, str]],
        trigger_reason: str,
    ) -> str:
        """
        Produce a concise, human-readable explanation covering:
          - What was the dominant risk
          - Why the decision was made
          - What risks were detected
          - What it means in practice
        """
        if decision == DecisionVerdict.ALLOW and risk_level == RiskLevel.LOW:
            active = [self.CATEGORY_LABELS.get(c, c) for c, s in categories.items() if s > 0]
            if not active:
                return "No significant risks detected. The skill appears safe."
            return (
                f"Minor {active[0]} detected but within acceptable thresholds. "
                f"Overall risk level is low."
            )

        # Gather active categories
        active_cats = sorted(
            [(c, s) for c, s in categories.items() if s > 0],
            key=lambda x: x[1],
            reverse=True,
        )

        if not active_cats:
            return "Elevated risk score with no specific category attribution."

        # Dominance detection
        total_score = sum(s for _, s in active_cats)
        primary_cat, primary_score = active_cats[0]
        dominance_ratio = primary_score / total_score if total_score > 0 else 0
        primary_label = self.CATEGORY_LABELS.get(primary_cat, primary_cat)

        # Enrich with complexity/signal
        enrichment = self._enrich_description(primary_cat, features)
        if enrichment:
            primary_desc = f"{enrichment} {primary_label}"
        else:
            primary_desc = primary_label

        # Build explanation parts
        parts = []

        # Lead with the primary finding
        parts.append(f"Detected {primary_desc}")

        # Secondary categories
        secondary = [self.CATEGORY_LABELS.get(c, c) for c, _ in active_cats[1:]]
        if secondary:
            parts.append(f" with {', '.join(secondary)}")

        # Spread context
        spread = str(features.get("file_spread", "none"))
        if spread == "widespread":
            parts.append(" across a wide file surface")
        elif spread == "moderate":
            parts.append(" across multiple files")

        parts.append(". ")

        # Dominance callout
        if dominance_ratio >= 0.6 and len(active_cats) > 1:
            parts.append(
                f"{primary_label.capitalize()} is the dominant risk factor "
                f"({dominance_ratio:.0%} of total risk). "
            )

        # Trigger reason
        parts.append(f"Decision: {trigger_reason}.")

        return "".join(parts)

    def _enrich_description(
        self, category: str, features: Dict[str, Union[bool, int, str]],
    ) -> Optional[str]:
        """Return a severity/signal qualifier for the primary category."""
        if category == "code_execution":
            return self.COMPLEXITY_LABELS.get(
                str(features.get("execution_complexity", "none"))
            )
        if category == "prompt_injection":
            return self.SIGNAL_LABELS.get(
                str(features.get("injection_signal", "none"))
            )
        return None

    # ------------------------------------------------------------------ #
    #  7. Recommendation mapping
    # ------------------------------------------------------------------ #

    def _map_recommendation(
        self, decision: DecisionVerdict, risk_level: RiskLevel,
    ) -> str:
        """Map (decision, risk_level) → actionable guidance string."""
        rec = self.policy.get("recommendations", {})
        if decision == DecisionVerdict.ALLOW:
            return rec.get("allow", "Safe to install.")
        if decision == DecisionVerdict.WARN:
            return rec.get("warn", "Install with caution.")
        # block
        if risk_level == RiskLevel.CRITICAL:
            return rec.get("block_critical", "Do not install.")
        return rec.get("block_high", "Manual review required.")
