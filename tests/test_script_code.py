import shutil
import tempfile
import unittest

from agentlens.analyzers.script_code import ScriptCodeAnalyzer
from agentlens.engines.scoring import ScoringEngine


class TestScriptCodeAnalyzer(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_detects_child_process_and_review_required(self):
        path = f"{self.tmpdir}/index.js"
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "const cp = require('node:child_process');\n"
                "cp.exec('id');\n"
            )

        findings = ScriptCodeAnalyzer().analyze(self.tmpdir)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("JS_CHILD_PROCESS", rule_ids)
        self.assertIn("JS_TS_REVIEW_REQUIRED", rule_ids)

    def test_detects_eval_in_typescript(self):
        path = f"{self.tmpdir}/index.ts"
        with open(path, "w", encoding="utf-8") as f:
            f.write("export const run = (src: string) => eval(src);\n")

        findings = ScriptCodeAnalyzer().analyze(self.tmpdir)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("JS_DYNAMIC_EVAL", rule_ids)

    def test_benign_js_still_requires_review_and_avoids_allow(self):
        path = f"{self.tmpdir}/index.js"
        with open(path, "w", encoding="utf-8") as f:
            f.write("module.exports = function sum(a, b) { return a + b; };\n")

        findings = ScriptCodeAnalyzer().analyze(self.tmpdir)
        result = ScoringEngine().calculate(findings)

        self.assertEqual(result["features"]["execution_type"], "unreviewed_script_runtime")
        self.assertEqual(result["decision"], "warn")

    def test_detects_js_obfuscation_and_dynamic_decoding(self):
        path = f"{self.tmpdir}/obfuscated.js"
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "const stage = Buffer.from(payload, 'base64').toString('utf8');\n"
                "const hidden = '\\x65\\x76\\x61\\x6c';\n"
            )

        findings = ScriptCodeAnalyzer().analyze(self.tmpdir)
        obfuscation = [f for f in findings if f.rule_id == "JS_OBFUSCATION_ATTEMPT"]

        self.assertTrue(obfuscation)
        self.assertTrue(all(f.severity.value == "high" for f in obfuscation))


if __name__ == "__main__":
    unittest.main()
