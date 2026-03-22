from typing import Dict, List, Union

class DecisionEngine:
    """
    Final decision layer: takes category scores + features and produces
    a clear decision with a human-readable reason.
    """
    
    # Templates for reason fragments per category
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

    def evaluate(
        self,
        risk_score: float,
        categories: Dict[str, float],
        features: Dict[str, Union[bool, int, str]],
        thresh_medium: float,
        thresh_high: float,
        thresh_critical: float,
    ) -> Dict[str, str]:
        """
        Returns:
            {
                "risk_level": "medium",
                "decision": "warn",
                "reason": "Detected code execution capability with moderate prompt injection signals"
            }
        """
        # --- Risk level ---
        if risk_score >= thresh_critical:
            risk_level = "critical"
            decision = "block"
        elif risk_score >= thresh_high:
            risk_level = "high"
            decision = "block"
        elif risk_score >= thresh_medium:
            risk_level = "medium"
            decision = "warn"
        else:
            risk_level = "low"
            decision = "allow"

        # --- Build reason ---
        reason = self._build_reason(risk_level, categories, features)

        return {
            "risk_level": risk_level,
            "decision": decision,
            "reason": reason,
        }

    def _build_reason(
        self,
        risk_level: str,
        categories: Dict[str, float],
        features: Dict[str, Union[bool, int, str]],
    ) -> str:
        if risk_level == "low":
            active = [self.CATEGORY_LABELS[c] for c, s in categories.items() if s > 0]
            if not active:
                return "No significant risks detected."
            return f"Minor {active[0]} detected; within acceptable thresholds."

        # Gather active category descriptions sorted by score descending
        active_cats = sorted(
            [(c, s) for c, s in categories.items() if s > 0],
            key=lambda x: x[1],
            reverse=True,
        )

        if not active_cats:
            return "Elevated risk score with no specific category attribution."

        # Primary signal
        primary_cat, primary_score = active_cats[0]
        primary_label = self.CATEGORY_LABELS.get(primary_cat, primary_cat)

        # Enrich with complexity if available
        complexity = None
        if primary_cat == "code_execution":
            complexity = self.COMPLEXITY_LABELS.get(
                str(features.get("execution_complexity", "none"))
            )
        elif primary_cat == "prompt_injection":
            sig = str(features.get("injection_signal", "none"))
            complexity = {"strong": "strong", "medium": "moderate", "weak": "weak"}.get(sig)

        if complexity:
            primary_desc = f"{complexity} {primary_label}"
        else:
            primary_desc = primary_label

        # Secondary signals
        secondary = [self.CATEGORY_LABELS.get(c, c) for c, _ in active_cats[1:]]

        # Spread context
        spread = str(features.get("file_spread", "none"))
        spread_suffix = ""
        if spread == "widespread":
            spread_suffix = " across a wide file surface"
        elif spread == "moderate":
            spread_suffix = " across multiple files"

        # Compose
        parts = [f"Detected {primary_desc}"]
        if secondary:
            parts.append(f" with {', '.join(secondary)}")
        parts.append(spread_suffix)
        parts.append(".")

        return "".join(parts)
