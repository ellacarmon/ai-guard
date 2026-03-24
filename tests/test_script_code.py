import os
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

    def test_does_not_flag_generic_buffer_from_usage(self):
        path = f"{self.tmpdir}/buffer.js"
        with open(path, "w", encoding="utf-8") as f:
            f.write("const data = Buffer.from('hello world');\n")

        findings = ScriptCodeAnalyzer().analyze(self.tmpdir)
        obfuscation = [f for f in findings if f.rule_id == "JS_OBFUSCATION_ATTEMPT"]

        self.assertFalse(obfuscation)

    def test_atob_without_dynamic_execution_context_is_not_flagged(self):
        path = f"{self.tmpdir}/decode.js"
        with open(path, "w", encoding="utf-8") as f:
            f.write("const decoded = atob(payload);\n")

        findings = ScriptCodeAnalyzer().analyze(self.tmpdir)
        obfuscation = [f for f in findings if f.rule_id == "JS_OBFUSCATION_ATTEMPT"]

        self.assertFalse(obfuscation)

    def test_atob_inside_eval_is_flagged(self):
        path = f"{self.tmpdir}/dynamic.js"
        with open(path, "w", encoding="utf-8") as f:
            f.write("eval(atob(payload));\n")

        findings = ScriptCodeAnalyzer().analyze(self.tmpdir)
        obfuscation = [f for f in findings if f.rule_id == "JS_OBFUSCATION_ATTEMPT"]

        self.assertTrue(obfuscation)

    def test_build_artifact_string_from_char_code_is_not_treated_as_obfuscation(self):
        build_dir = f"{self.tmpdir}/package/build"
        os.makedirs(build_dir, exist_ok=True)
        path = f"{build_dir}/index.js"
        with open(path, "w", encoding="utf-8") as f:
            f.write("const text = String.fromCharCode(122, 120);\n")

        findings = ScriptCodeAnalyzer().analyze(self.tmpdir)
        obfuscation = [f for f in findings if f.rule_id == "JS_OBFUSCATION_ATTEMPT"]

        self.assertFalse(obfuscation)

    def test_cjs_bundle_dense_escapes_are_not_treated_as_obfuscation(self):
        path = f"{self.tmpdir}/bundle.cjs"
        with open(path, "w", encoding="utf-8") as f:
            f.write("const text = '\\x61\\x62\\x63\\x64';\n")

        findings = ScriptCodeAnalyzer().analyze(self.tmpdir)
        obfuscation = [f for f in findings if f.rule_id == "JS_OBFUSCATION_ATTEMPT"]

        self.assertFalse(obfuscation)

    def test_build_artifact_explicit_base64_decode_is_still_flagged(self):
        build_dir = f"{self.tmpdir}/dist"
        os.makedirs(build_dir, exist_ok=True)
        path = f"{build_dir}/index.js"
        with open(path, "w", encoding="utf-8") as f:
            f.write("const stage = Buffer.from(payload, 'base64').toString('utf8');\n")

        findings = ScriptCodeAnalyzer().analyze(self.tmpdir)
        obfuscation = [f for f in findings if f.rule_id == "JS_OBFUSCATION_ATTEMPT"]

        self.assertTrue(obfuscation)


if __name__ == "__main__":
    unittest.main()
