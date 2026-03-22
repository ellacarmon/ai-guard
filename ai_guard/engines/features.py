from typing import List, Dict, Union
from ..models.schema import Finding, Category, Severity

class FeatureExtractor:
    """
    Abstraction layer: findings → features → category scores.
    
    Produces three tiers of features:
    1. Primitive: boolean presence of specific rule triggers
    2. Derived: signal strength (weak/medium/strong) based on severity + confidence + context
    3. Aggregate: category-level summaries
    """
    
    # Map rule_id → primitive boolean features
    FEATURE_RULES = {
        "has_dynamic_exec": {
            "type": "bool",
            "match_rules": ["CODE_DYNAMIC_EXECUTION"],
        },
        "has_shell_exec": {
            "type": "bool",
            "match_rules": ["CODE_SHELL_EXECUTION"],
        },
        "has_subprocess": {
            "type": "bool",
            "match_rules": ["CODE_SUBPROCESS"],
        },
        "has_os_command": {
            "type": "bool",
            "match_rules": ["CODE_OS_SYSTEM"],
        },
    }

    # Category-level aggregate features
    CATEGORY_FEATURES = {
        "has_code_execution": Category.CODE_EXECUTION,
        "has_prompt_injection": Category.PROMPT_INJECTION,
        "has_supply_chain_risk": Category.SUPPLY_CHAIN,
        "has_filesystem_access": Category.FILESYSTEM_ACCESS,
        "has_network_access": Category.NETWORK_ACCESS,
    }

    # Severity hierarchy for complexity derivation (highest to lowest)
    EXEC_SEVERITY_LADDER = [
        ("has_dynamic_exec", "critical"),   # eval/exec = critical complexity
        ("has_shell_exec", "high"),          # shell=True = high complexity
        ("has_os_command", "high"),          # os.system = high complexity
        ("has_subprocess", "low"),           # subprocess(shell=False) = low complexity
    ]

    # Severity weights for signal strength computation
    SEVERITY_SIGNAL = {
        Severity.CRITICAL: 3.0,
        Severity.HIGH: 2.0,
        Severity.MEDIUM: 1.0,
        Severity.LOW: 0.5,
    }

    def extract(self, findings: List[Finding]) -> Dict[str, Union[bool, int, str]]:
        """Transform raw findings into a structured feature dictionary."""
        features: Dict[str, Union[bool, int, str]] = {}
        
        # --- Tier 1: Primitive features (bool only, no raw counts) ---
        for feature_key, spec in self.FEATURE_RULES.items():
            matched = [f for f in findings if f.rule_id in spec["match_rules"]]
            features[feature_key] = len(matched) > 0

        # Category-level aggregates
        for feature_key, category in self.CATEGORY_FEATURES.items():
            features[feature_key] = any(f.category == category for f in findings)

        # Cross-cutting stats
        features["total_findings"] = len(findings)
        features["critical_finding_count"] = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        features["high_confidence_count"] = sum(1 for f in findings if getattr(f, 'confidence', 1.0) >= 0.8)
        features["unique_files_affected"] = len(set(f.file_path for f in findings))
        
        # --- Tier 2: Derived signal strength features ---
        features["execution_complexity"] = self._derive_complexity(
            features, self.EXEC_SEVERITY_LADDER
        )
        features["execution_signal"] = self._derive_signal_strength(
            findings, Category.CODE_EXECUTION
        )
        features["injection_signal"] = self._derive_signal_strength(
            findings, Category.PROMPT_INJECTION
        )
        features["file_spread"] = self._derive_spread(features)
        
        return features
    
    def _derive_complexity(
        self, features: Dict, ladder: list
    ) -> str:
        """
        Walk the severity ladder top-down. Return the highest triggered level.
        If nothing triggered, return 'none'.
        """
        for feature_key, level in ladder:
            val = features.get(feature_key, False)
            if val and val is not False:
                return level
        return "none"
    
    def _derive_signal_strength(
        self, findings: List[Finding], category: Category
    ) -> str:
        """
        Classify signal strength for a category based on:
        - Highest severity of any finding
        - Average confidence of findings
        - Whether findings appear in code (high trust) vs docs (low trust)
        
        Returns: none / weak / medium / strong
        """
        cat_findings = [f for f in findings if f.category == category]
        if not cat_findings:
            return "none"
        
        # Compute max severity signal
        max_severity = max(
            self.SEVERITY_SIGNAL.get(f.severity, 0.0) for f in cat_findings
        )
        
        # Compute average confidence
        avg_confidence = sum(
            getattr(f, 'confidence', 1.0) for f in cat_findings
        ) / len(cat_findings)
        
        # Combined signal = severity weight * confidence
        signal = max_severity * avg_confidence
        
        if signal >= 2.5:
            return "strong"
        elif signal >= 1.5:
            return "medium"
        elif signal > 0:
            return "weak"
        return "none"
    
    def _derive_spread(self, features: Dict) -> str:
        """How widespread are findings across the codebase."""
        unique = features.get("unique_files_affected", 0)
        if unique == 0:
            return "none"
        elif unique <= 2:
            return "isolated"
        elif unique <= 10:
            return "moderate"
        else:
            return "widespread"
