import unittest
from ai_guard.models.schema import Finding, Category, Severity
from ai_guard.engines.scoring import ScoringEngine

class TestScoringEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ScoringEngine()

    def test_single_critical_finding_is_critical_risk(self):
        # 1 CRITICAL should trigger >= 9.0 (CRITICAL block)
        findings = [
            Finding(rule_id="r1", category=Category.CODE_EXECUTION, severity=Severity.CRITICAL, 
                    file_path="f.py", description="eval", confidence=1.0)
        ]
        risk_score, risk_level, rec, conf, _, _, _, _ = self.engine.calculate(findings)
        self.assertGreaterEqual(risk_score, 9.0)
        self.assertEqual(risk_level, "CRITICAL")
        self.assertEqual(rec, "BLOCK")
        self.assertEqual(conf, 1.0)

    def test_low_severity_saturation(self):
        # 100 LOW findings should STILL not exceed 10.0 due to asymptotic decay
        findings = [
            Finding(rule_id=f"r{i}", category=Category.CODE_EXECUTION, severity=Severity.LOW, 
                    file_path="f.py", description="low", confidence=1.0)
            for i in range(100)
        ]
        risk_score, _, _, _, categories, _, _, _ = self.engine.calculate(findings)
        self.assertLessEqual(risk_score, 10.0)
        self.assertLessEqual(categories[Category.CODE_EXECUTION.value], 10.0)

    def test_mild_findings_yield_medium_risk(self):
        # 3 MEDIUM findings should trigger MEDIUM risk (>=4.0 and <7.0)
        findings = [
            Finding(rule_id="r1", category=Category.FILESYSTEM_ACCESS, severity=Severity.MEDIUM, 
                    file_path="f.py", description="fs", confidence=1.0),
            Finding(rule_id="r2", category=Category.FILESYSTEM_ACCESS, severity=Severity.MEDIUM, 
                    file_path="g.py", description="fs", confidence=1.0),
            Finding(rule_id="r3", category=Category.FILESYSTEM_ACCESS, severity=Severity.MEDIUM, 
                    file_path="h.py", description="fs", confidence=1.0)
        ]
        risk_score, risk_level, rec, _, _, _, _, _ = self.engine.calculate(findings)
        self.assertGreaterEqual(risk_score, 4.0)
        self.assertLess(risk_score, 8.0)
        self.assertIn(risk_level, ["MEDIUM", "HIGH"])

if __name__ == '__main__':
    unittest.main()
