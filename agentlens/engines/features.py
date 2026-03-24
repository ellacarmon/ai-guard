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
        # --- Existing code execution primitives ---
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
        "has_js_dynamic_exec": {
            "type": "bool",
            "match_rules": ["JS_DYNAMIC_EVAL", "JS_STRING_TIMER_EVAL"],
        },
        "has_js_child_process": {
            "type": "bool",
            "match_rules": ["JS_CHILD_PROCESS"],
        },
        "has_unreviewed_script_runtime": {
            "type": "bool",
            "match_rules": ["JS_TS_REVIEW_REQUIRED"],
        },
        # --- Paper: Agent Hijacker patterns (P1, P2, P4) ---
        "has_instruction_override": {
            "type": "bool",
            "match_rules": ["SKILL_INSTRUCTION_OVERRIDE"],
        },
        "has_hidden_instructions": {
            "type": "bool",
            "match_rules": ["SKILL_HIDDEN_INSTRUCTIONS"],
        },
        "has_behavior_manipulation": {
            "type": "bool",
            "match_rules": ["SKILL_BEHAVIOR_MANIPULATION"],
        },
        # --- Paper: Data Thief patterns (E2, PE3, SC2, SC3) ---
        "has_credential_harvest": {
            "type": "bool",
            "match_rules": ["SKILL_CREDENTIAL_HARVEST", "SKILL_CREDENTIAL_FILE_ACCESS"],
        },
        "has_remote_exec": {
            "type": "bool",
            "match_rules": ["SKILL_REMOTE_SCRIPT_EXEC"],
        },
        "has_obfuscation": {
            "type": "bool",
            "match_rules": [
                "SKILL_OBFUSCATED_CODE",
                "SC3",
                "CODE_OBFUSCATION_DETECTED",
                "JS_OBFUSCATION_ATTEMPT",
            ],
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
        ("has_js_dynamic_exec", "critical"),   # JS eval/Function/string timers
        ("has_shell_exec", "high"),          # shell=True = high complexity
        ("has_os_command", "high"),          # os.system = high complexity
        ("has_js_child_process", "high"),    # child_process exec/spawn/fork
        ("has_unreviewed_script_runtime", "high"),  # fail closed on partial runtime coverage
        ("has_subprocess", "low"),           # subprocess(shell=False) = low complexity
    ]

    # Severity weights for signal strength computation
    SEVERITY_SIGNAL = {
        Severity.CRITICAL: 3.0,
        Severity.HIGH: 2.0,
        Severity.MEDIUM: 1.0,
        Severity.LOW: 0.5,
    }

    def extract(self, findings: List[Finding], context: Dict = None) -> Dict[str, Union[bool, int, str]]:
        """Transform raw findings into a structured feature dictionary."""
        if context is None:
            context = {}
            
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
        
        # Push context signals into features
        features["is_framework"] = context.get("is_framework", False)
        features["is_library"] = context.get("is_library", False)
        features["exec_exposed_to_user"] = context.get("exec_exposed_to_user", True)
        
        # --- Tier 2: Derived signal strength features ---
        features["execution_type"] = self._derive_execution_type(features, context)
        
        # --- Exploitability features ---
        features["execution_exposed_to_user"] = context.get("execution_exposed_to_user", features["exec_exposed_to_user"])
        features["input_reaches_sensitive_function"] = context.get("input_reaches_sensitive_function", features.get("has_prompt_injection", False))
        features["control_flow_reachable"] = context.get("control_flow_reachable", True)
        features["unsafe_execution_pattern"] = features.get("execution_type") in ["shell_execution", "dynamic_eval"]
        features["sandbox_presence"] = context.get("sandbox_presence", False)

        # Note: maintaining execution_complexity for backward-compatibility with tests / UI if needed,
        # but execution_type is the new driving feature.
        features["execution_complexity"] = self._derive_complexity(
            features, self.EXEC_SEVERITY_LADDER
        )
        features["execution_signal"] = self._derive_signal_strength(
            findings, Category.CODE_EXECUTION
        )
        if features.get("execution_type") == "safe_runtime_execution":
            features["execution_signal"] = "weak"
            features["execution_complexity"] = "low"
            
        features["injection_signal"] = self._derive_signal_strength(
            findings, Category.PROMPT_INJECTION
        )
        features["file_spread"] = self._derive_spread(features)

        # --- Tier 3: Compound archetype fingerprints (paper-derived) ---
        # Data Thief: E2 + SC2 co-occurrence (paper OR=556, 97.6% sensitivity against factory actors)
        features["has_data_thief_fingerprint"] = bool(
            features.get("has_credential_harvest") and features.get("has_remote_exec")
        )

        # Agent Hijacker: any P1/P2/P4 pattern in skill documentation
        features["has_agent_hijacker_fingerprint"] = bool(
            features.get("has_instruction_override")
            or features.get("has_hidden_instructions")
            or features.get("has_behavior_manipulation")
        )

        # High-confidence obfuscation evasion (advanced sophistication — Level 3 in paper)
        features["has_evasion"] = bool(
            features.get("has_obfuscation") or features.get("has_hidden_instructions")
        )

        # Attack archetype classification (mutually exclusive, data thief takes priority)
        if features["has_data_thief_fingerprint"]:
            features["attack_archetype"] = "data_thief"
        elif features["has_agent_hijacker_fingerprint"]:
            features["attack_archetype"] = "agent_hijacker"
        else:
            features["attack_archetype"] = "none"

        return features

    def _derive_execution_type(self, features: Dict, context: Dict) -> str:
        base_type = "none"
        if features.get("has_dynamic_exec") or features.get("has_js_dynamic_exec"):
            base_type = "dynamic_eval"
        elif (
            features.get("has_shell_exec")
            or features.get("has_os_command")
            or features.get("has_js_child_process")
        ):
            base_type = "shell_execution"
        elif features.get("has_subprocess"):
            base_type = "subprocess"
        elif features.get("has_unreviewed_script_runtime"):
            base_type = "unreviewed_script_runtime"
            
        if base_type != "none":
            if context.get("is_framework", False):
                if base_type == "dynamic_eval":
                    return "safe_runtime_execution"
        return base_type

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
