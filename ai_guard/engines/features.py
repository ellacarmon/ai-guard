from typing import List, Dict, Union
from ..models.schema import Finding, Category

class FeatureExtractor:
    """
    Abstraction layer that transforms raw findings into structured 
    boolean/count features before they feed into category scoring.
    
    Pipeline: findings → features → category scores
    """
    
    # Map rule_id prefixes to feature keys
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
        "prompt_override_patterns": {
            "type": "count",
            "match_rules": ["PROMPT_INJECTION_OVERRIDE"],
        },
        "prompt_exfil_patterns": {
            "type": "count",
            "match_rules": ["PROMPT_INJECTION_EXFIL"],
        },
    }

    # Category-level aggregate features derived from findings
    CATEGORY_FEATURES = {
        "has_code_execution": Category.CODE_EXECUTION,
        "has_prompt_injection": Category.PROMPT_INJECTION,
        "has_supply_chain_risk": Category.SUPPLY_CHAIN,
        "has_filesystem_access": Category.FILESYSTEM_ACCESS,
        "has_network_access": Category.NETWORK_ACCESS,
    }

    def extract(self, findings: List[Finding]) -> Dict[str, Union[bool, int]]:
        """Transform raw findings into a structured feature dictionary."""
        features: Dict[str, Union[bool, int]] = {}
        
        # Rule-level features
        for feature_key, spec in self.FEATURE_RULES.items():
            matched = [f for f in findings if f.rule_id in spec["match_rules"]]
            if spec["type"] == "bool":
                features[feature_key] = len(matched) > 0
            elif spec["type"] == "count":
                features[feature_key] = len(matched)

        # Category-level aggregate features
        for feature_key, category in self.CATEGORY_FEATURES.items():
            features[feature_key] = any(f.category == category for f in findings)

        # Derived / cross-cutting features
        features["total_findings"] = len(findings)
        features["critical_finding_count"] = sum(1 for f in findings if f.severity.value == "critical")
        features["high_confidence_count"] = sum(1 for f in findings if getattr(f, 'confidence', 1.0) >= 0.8)
        features["unique_files_affected"] = len(set(f.file_path for f in findings))
        
        return features
