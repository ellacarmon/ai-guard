import unittest

from agentlens.models.schema import (
    Finding, Category, Severity,
    ExploitabilityLevel,
)
from agentlens.engines.scoring import ScoringEngine
from agentlens.engines.features import FeatureExtractor


def _finding(rule_id, category, severity, file_path="skill.py", confidence=1.0):
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        file_path=file_path,
        description=f"Test finding for {rule_id}",
        confidence=confidence,
    )


class TestDataThiefArchetype(unittest.TestCase):
    """Data Thief = E2 (credential harvest) + SC2 (remote exec) co-occurrence."""

    def setUp(self):
        self.engine = ScoringEngine()

    def test_data_thief_fingerprint_detected(self):
        findings = [
            _finding("SKILL_CREDENTIAL_HARVEST", Category.SUPPLY_CHAIN, Severity.CRITICAL),
            _finding("SKILL_REMOTE_SCRIPT_EXEC", Category.SUPPLY_CHAIN, Severity.CRITICAL),
        ]
        result = self.engine.calculate(findings)
        features = result["features"]

        self.assertTrue(features["has_data_thief_fingerprint"], "Data Thief fingerprint should be detected")
        self.assertEqual(features["attack_archetype"], "data_thief")
        self.assertEqual(result["decision"], "block", "Should block on Data Thief fingerprint")

    def test_data_thief_exploitability_critical(self):
        findings = [
            _finding("SKILL_CREDENTIAL_HARVEST", Category.SUPPLY_CHAIN, Severity.CRITICAL),
            _finding("SKILL_REMOTE_SCRIPT_EXEC", Category.SUPPLY_CHAIN, Severity.CRITICAL),
        ]
        result = self.engine.calculate(findings)
        exp = result["exploitability"]

        self.assertEqual(exp.exploitability_level, ExploitabilityLevel.CRITICAL)
        self.assertEqual(exp.attack_archetype, "data_thief")
        self.assertGreaterEqual(exp.exploitability_score, 9.0)

    def test_credential_harvest_alone_no_fingerprint(self):
        """Credential harvesting alone should NOT trigger the full Data Thief fingerprint."""
        findings = [
            _finding("SKILL_CREDENTIAL_HARVEST", Category.SUPPLY_CHAIN, Severity.CRITICAL),
        ]
        result = self.engine.calculate(findings)
        features = result["features"]

        self.assertFalse(features["has_data_thief_fingerprint"])
        self.assertNotEqual(features["attack_archetype"], "data_thief")

    def test_data_thief_with_obfuscation_evasion(self):
        """Data Thief + obfuscation = Level 3 advanced — should score max."""
        findings = [
            _finding("SKILL_CREDENTIAL_HARVEST", Category.SUPPLY_CHAIN, Severity.CRITICAL),
            _finding("SKILL_REMOTE_SCRIPT_EXEC", Category.SUPPLY_CHAIN, Severity.CRITICAL),
            _finding("SKILL_OBFUSCATED_CODE", Category.SUPPLY_CHAIN, Severity.CRITICAL),
        ]
        result = self.engine.calculate(findings)
        features = result["features"]

        self.assertTrue(features["has_evasion"])
        self.assertEqual(result["decision"], "block")


class TestAgentHijackerArchetype(unittest.TestCase):
    """Agent Hijacker = P1/P2/P4 instruction-level subversion."""

    def setUp(self):
        self.engine = ScoringEngine()

    def test_instruction_override_plus_behavior_manipulation(self):
        """Combined P1 + P4 = full Agent Hijacker archetype."""
        findings = [
            _finding("SKILL_INSTRUCTION_OVERRIDE", Category.PROMPT_INJECTION, Severity.HIGH, "SKILL.md"),
            _finding("SKILL_BEHAVIOR_MANIPULATION", Category.PROMPT_INJECTION, Severity.MEDIUM, "SKILL.md"),
        ]
        result = self.engine.calculate(findings)
        features = result["features"]
        exp = result["exploitability"]

        self.assertTrue(features["has_agent_hijacker_fingerprint"])
        self.assertEqual(features["attack_archetype"], "agent_hijacker")
        self.assertEqual(exp.exploitability_level, ExploitabilityLevel.CRITICAL)
        self.assertEqual(exp.attack_archetype, "agent_hijacker")
        self.assertEqual(result["decision"], "block")

    def test_standalone_instruction_override(self):
        """P1 alone should be HIGH exploitability and trigger warn/block."""
        findings = [
            _finding("SKILL_INSTRUCTION_OVERRIDE", Category.PROMPT_INJECTION, Severity.HIGH, "SKILL.md"),
        ]
        result = self.engine.calculate(findings)
        exp = result["exploitability"]

        self.assertIn(exp.exploitability_level, [ExploitabilityLevel.HIGH, ExploitabilityLevel.CRITICAL])
        self.assertNotEqual(result["decision"], "allow")

    def test_standalone_behavior_manipulation_no_block(self):
        """P4 alone (medium severity per paper) should warn, NOT block immediately."""
        findings = [
            _finding("SKILL_BEHAVIOR_MANIPULATION", Category.PROMPT_INJECTION, Severity.MEDIUM, "SKILL.md", confidence=0.9),
        ]
        result = self.engine.calculate(findings)

        # P4 standalone should not reach a block — it's a supporting technique
        self.assertIn(result["decision"], ["allow", "warn"], "Standalone P4 should not block")

    def test_agent_hijacker_no_code_execution_required(self):
        """Agent Hijacker operates entirely in natural language — no code execution needed."""
        findings = [
            _finding("SKILL_INSTRUCTION_OVERRIDE", Category.PROMPT_INJECTION, Severity.HIGH, "SKILL.md"),
            _finding("SKILL_HIDDEN_INSTRUCTIONS", Category.PROMPT_INJECTION, Severity.HIGH, "SKILL.md"),
        ]
        result = self.engine.calculate(findings)
        features = result["features"]

        # Should have no code execution
        self.assertFalse(features.get("has_code_execution", False))
        # But still be exploitable
        self.assertTrue(result["exploitability"].is_exploitable)


class TestBenignSkillNoFalsePositive(unittest.TestCase):
    """Verify benign skills are not flagged under the new rules."""

    def setUp(self):
        self.engine = ScoringEngine()

    def test_benign_no_findings(self):
        result = self.engine.calculate([])
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["exploitability"].attack_archetype, None)

    def test_benign_findings_no_archetype(self):
        """Network access + filesystem access alone should not trigger archetypes."""
        from agentlens.models.schema import Category
        findings = [
            _finding("NET_ACCESS", Category.NETWORK_ACCESS, Severity.LOW),
            _finding("FS_ACCESS", Category.FILESYSTEM_ACCESS, Severity.MEDIUM),
        ]
        result = self.engine.calculate(findings)
        features = result["features"]

        self.assertFalse(features.get("has_data_thief_fingerprint"))
        self.assertFalse(features.get("has_agent_hijacker_fingerprint"))
        self.assertEqual(features.get("attack_archetype"), "none")


class TestFeatureExtractorArchetypes(unittest.TestCase):
    """Unit tests directly on the FeatureExtractor."""

    def test_data_thief_features_extracted(self):
        findings = [
            _finding("SKILL_CREDENTIAL_HARVEST", Category.SUPPLY_CHAIN, Severity.CRITICAL),
            _finding("SKILL_REMOTE_SCRIPT_EXEC", Category.SUPPLY_CHAIN, Severity.CRITICAL),
        ]
        extractor = FeatureExtractor()
        features = extractor.extract(findings)

        self.assertTrue(features["has_credential_harvest"])
        self.assertTrue(features["has_remote_exec"])
        self.assertTrue(features["has_data_thief_fingerprint"])
        self.assertEqual(features["attack_archetype"], "data_thief")

    def test_agent_hijacker_features_extracted(self):
        findings = [
            _finding("SKILL_INSTRUCTION_OVERRIDE", Category.PROMPT_INJECTION, Severity.HIGH),
            _finding("SKILL_BEHAVIOR_MANIPULATION", Category.PROMPT_INJECTION, Severity.MEDIUM),
        ]
        extractor = FeatureExtractor()
        features = extractor.extract(findings)

        self.assertTrue(features["has_instruction_override"])
        self.assertTrue(features["has_behavior_manipulation"])
        self.assertTrue(features["has_agent_hijacker_fingerprint"])
        self.assertEqual(features["attack_archetype"], "agent_hijacker")

    def test_evasion_flag(self):
        findings = [
            _finding("SKILL_OBFUSCATED_CODE", Category.SUPPLY_CHAIN, Severity.CRITICAL),
        ]
        extractor = FeatureExtractor()
        features = extractor.extract(findings)

        self.assertTrue(features["has_obfuscation"])
        self.assertTrue(features["has_evasion"])


if __name__ == "__main__":
    unittest.main()
