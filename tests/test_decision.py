import unittest
from agentlens.models.schema import Finding, Category, Severity
from agentlens.engines.decision import DecisionEngine


class TestDecisionEngine(unittest.TestCase):
    """Unit tests for the production-grade DecisionEngine."""

    def setUp(self):
        self.engine = DecisionEngine()

    # ------------------------------------------------------------------ #
    #  Basic threshold tests
    # ------------------------------------------------------------------ #

    def test_low_risk_allows(self):
        result = self.engine.evaluate(
            risk_score=2.0,
            categories={"code_execution": 0.0, "prompt_injection": 0.0},
            features={},
        )
        self.assertEqual(result.decision.value, "allow")
        self.assertEqual(result.risk_level.value, "low")
        self.assertIn("Safe to install", result.recommendation)

    def test_medium_risk_warns(self):
        result = self.engine.evaluate(
            risk_score=5.0,
            categories={"code_execution": 5.0, "prompt_injection": 0.0},
            features={"execution_complexity": "high", "execution_signal": "medium"},
        )
        self.assertEqual(result.decision.value, "warn")

    def test_high_risk_blocks(self):
        result = self.engine.evaluate(
            risk_score=8.5,
            categories={"code_execution": 8.0, "prompt_injection": 3.0},
            features={"execution_complexity": "critical", "execution_signal": "strong"},
        )
        self.assertEqual(result.decision.value, "block")

    # ------------------------------------------------------------------ #
    #  Category dominance
    # ------------------------------------------------------------------ #

    def test_category_dominance_in_explanation(self):
        result = self.engine.evaluate(
            risk_score=7.0,
            categories={
                "prompt_injection": 8.0,
                "code_execution": 1.0,
                "supply_chain": 0.0,
            },
            features={"injection_signal": "strong"},
        )
        self.assertIn("dominant", result.explanation.lower())

    # ------------------------------------------------------------------ #
    #  Combination rules
    # ------------------------------------------------------------------ #

    def test_combination_rule_triggers_block(self):
        """prompt_injection(5) + code_execution(5) should block even if overall score is moderate."""
        result = self.engine.evaluate(
            risk_score=6.0,
            categories={"prompt_injection": 5.0, "code_execution": 5.0},
            features={"injection_signal": "medium", "execution_signal": "medium"},
        )
        self.assertEqual(result.decision.value, "block")
        self.assertIn("combined", result.explanation.lower())

    def test_combination_rule_does_not_fire_below_thresholds(self):
        """prompt_injection(3) + code_execution(3) should NOT trigger combination rule."""
        result = self.engine.evaluate(
            risk_score=3.5,
            categories={"prompt_injection": 3.0, "code_execution": 3.0},
            features={"injection_signal": "weak", "execution_signal": "weak"},
        )
        self.assertNotEqual(result.decision.value, "block")

    # ------------------------------------------------------------------ #
    #  Category overrides
    # ------------------------------------------------------------------ #

    def test_category_override_blocks(self):
        """Single category exceeding its block threshold should force block."""
        result = self.engine.evaluate(
            risk_score=6.0,
            categories={"prompt_injection": 8.0, "code_execution": 0.0},
            features={"injection_signal": "strong"},
        )
        self.assertEqual(result.decision.value, "block")

    # ------------------------------------------------------------------ #
    #  Confidence downgrade
    # ------------------------------------------------------------------ #

    def test_low_confidence_downgrades_block_to_warn(self):
        findings = [
            Finding(
                rule_id="CODE_DYNAMIC_EXECUTION",
                category=Category.CODE_EXECUTION,
                severity=Severity.CRITICAL,
                file_path="f.py",
                description="eval",
                confidence=0.2,
            )
        ]
        result = self.engine.evaluate(
            risk_score=9.0,
            categories={"code_execution": 9.0},
            features={
                "execution_complexity": "critical",
                "execution_signal": "weak",
                "unique_files_affected": 1,
            },
            findings=findings,
        )
        # Low confidence (0.2) should downgrade block → warn
        self.assertEqual(result.decision.value, "warn")
        self.assertLess(result.confidence, 0.5)

    def test_high_confidence_preserves_block(self):
        findings = [
            Finding(
                rule_id="CODE_DYNAMIC_EXECUTION",
                category=Category.CODE_EXECUTION,
                severity=Severity.CRITICAL,
                file_path="f.py",
                description="eval",
                confidence=1.0,
            ),
            Finding(
                rule_id="CODE_SHELL_EXECUTION",
                category=Category.CODE_EXECUTION,
                severity=Severity.HIGH,
                file_path="g.py",
                description="shell",
                confidence=0.9,
            ),
        ]
        result = self.engine.evaluate(
            risk_score=9.0,
            categories={"code_execution": 9.0},
            features={
                "execution_complexity": "critical",
                "execution_signal": "strong",
                "unique_files_affected": 2,
            },
            findings=findings,
        )
        self.assertEqual(result.decision.value, "block")
        self.assertGreaterEqual(result.confidence, 0.5)

    # ------------------------------------------------------------------ #
    #  Custom policy
    # ------------------------------------------------------------------ #

    def test_custom_policy_overrides(self):
        """A stricter policy should block at lower scores."""
        import tempfile
        import yaml

        strict_policy = {
            "decision": {
                "risk_levels": {"critical": 5.0, "high": 3.0, "medium": 1.0},
                "block_if": {
                    "risk_score": 3.0,
                    "categories": {},
                    "combinations": [],
                },
                "warn_if": {"risk_score": 1.0, "categories": {}},
                "confidence": {
                    "low_confidence_threshold": 0.5,
                    "downgrade_on_low_confidence": False,
                },
                "recommendations": {
                    "allow": "OK",
                    "warn": "Be careful",
                    "block_high": "Stop",
                    "block_critical": "Absolutely stop",
                },
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(strict_policy, f)
            f.flush()
            strict_engine = DecisionEngine(policy_path=f.name)

        result = strict_engine.evaluate(
            risk_score=4.0,
            categories={"code_execution": 4.0},
            features={},
        )
        self.assertEqual(result.decision.value, "block")
        self.assertEqual(result.risk_level.value, "high")

        import os
        os.unlink(f.name)

    # ------------------------------------------------------------------ #
    #  Explanation quality
    # ------------------------------------------------------------------ #

    def test_explanation_contains_top_risks(self):
        result = self.engine.evaluate(
            risk_score=7.5,
            categories={
                "prompt_injection": 7.0,
                "code_execution": 4.0,
                "supply_chain": 0.0,
            },
            features={"injection_signal": "strong", "execution_signal": "medium"},
        )
        self.assertIn("prompt injection", result.explanation.lower())
        self.assertTrue(len(result.explanation) > 20)

    # ------------------------------------------------------------------ #
    #  Output schema completeness
    # ------------------------------------------------------------------ #

    def test_output_schema_completeness(self):
        result = self.engine.evaluate(
            risk_score=5.0,
            categories={"code_execution": 5.0},
            features={},
        )
        # All required fields present
        self.assertIsNotNone(result.risk_score)
        self.assertIsNotNone(result.risk_level)
        self.assertIsNotNone(result.decision)
        self.assertIsNotNone(result.confidence)
        self.assertIsInstance(result.top_risks, list)
        self.assertIsInstance(result.explanation, str)
        self.assertIsInstance(result.recommendation, str)

    # ------------------------------------------------------------------ #
    #  Top risks ordering
    # ------------------------------------------------------------------ #

    def test_top_risks_ordered_by_score(self):
        result = self.engine.evaluate(
            risk_score=6.0,
            categories={
                "prompt_injection": 6.0,
                "code_execution": 3.0,
                "network_access": 1.0,
                "supply_chain": 0.0,
            },
            features={},
        )
        self.assertEqual(result.top_risks[0], "prompt_injection")
        self.assertEqual(result.top_risks[1], "code_execution")


if __name__ == "__main__":
    unittest.main()
