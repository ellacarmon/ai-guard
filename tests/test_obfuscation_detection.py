import base64

from agentlens.analyzers.ast_code import ASTCodeAnalyzer
from agentlens.analyzers.semantic import (
    SYSTEM_PROMPT,
    SemanticDecision,
    SemanticVerdict,
)
from agentlens.engines.hybrid import HybridEngine
from agentlens.engines.rules import RuleEngine
from agentlens.models.schema import Category, Finding, Severity


class _StubSemanticAnalyzer:
    confidence_threshold = 0.85

    def __init__(self, verdict: SemanticVerdict):
        self._verdict = verdict

    def analyze_snippets(self, findings):
        return self._verdict


def test_python_obfuscation_detection_from_exec_and_base64(tmp_path):
    sample = tmp_path / "payload.py"
    sample.write_text(
        'import base64\nexec(base64.b64decode("cHJpbnQoJ3B3bmVkJyk=").decode())\n',
        encoding="utf-8",
    )

    analyzer = ASTCodeAnalyzer(rule_engine=RuleEngine())
    findings = analyzer.analyze(str(tmp_path))

    rule_ids = {finding.rule_id for finding in findings}
    assert "CODE_DYNAMIC_EXECUTION" in rule_ids
    assert "CODE_OBFUSCATION_DETECTED" in rule_ids


def test_pth_import_lines_are_scanned_as_executable_code(tmp_path):
    sample = tmp_path / "sitecustomize.pth"
    sample.write_text(
        'import base64; exec(base64.b64decode("cHJpbnQoJ3B0aCcp").decode())\n',
        encoding="utf-8",
    )

    analyzer = ASTCodeAnalyzer(rule_engine=RuleEngine())
    findings = analyzer.analyze(str(tmp_path))

    obfuscation = [f for f in findings if f.rule_id == "CODE_OBFUSCATION_DETECTED"]
    assert obfuscation
    assert obfuscation[0].file_path == "sitecustomize.pth"
    assert obfuscation[0].line_number == 1


def test_high_entropy_base64_in_dynamic_exec_is_flagged(tmp_path):
    token = base64.b64encode(bytes(range(256))).decode("ascii")
    sample = tmp_path / "entropy.py"
    sample.write_text(f'eval("{token}")\n', encoding="utf-8")

    analyzer = ASTCodeAnalyzer(rule_engine=RuleEngine())
    findings = analyzer.analyze(str(tmp_path))

    assert any(
        finding.rule_id == "CODE_OBFUSCATION_DETECTED"
        and "high-entropy Base64 payload" in finding.description
        for finding in findings
    )


def test_hybrid_engine_reports_decoded_malicious_obfuscation():
    finding = Finding(
        rule_id="CODE_OBFUSCATION_DETECTED",
        category=Category.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        file_path="sitecustomize.pth",
        line_number=1,
        description="Obfuscation Detected: dynamic execution combined with base64.b64decode().",
        evidence='exec(base64.b64decode("...").decode())',
        confidence=0.98,
    )
    verdict = SemanticVerdict(
        decision=SemanticDecision.BLOCK,
        confidence_score=1.0,
        explanation="Decoded payload reads os.environ and sends secrets via requests.post.",
        flagged_pattern="decoded_exfiltration",
        decoded_malicious_payload=True,
    )

    engine = HybridEngine(_StubSemanticAnalyzer(verdict))
    result = engine.run([finding], context={})

    assert result["decision"] == "block"
    assert "[Critical] Malicious obfuscated payload detected and decoded." in result["explanation"]


def test_semantic_prompt_requires_speculative_base64_decoding():
    lowered = SYSTEM_PROMPT.lower()
    assert "speculatively decode" in lowered
    assert "base64-encoded strings" in lowered
    assert "os.environ" in SYSTEM_PROMPT
    assert "requests.post" in SYSTEM_PROMPT


def test_semantic_allow_overrides_high_only_static_block():
    findings = [
        Finding(
            rule_id="JS_CHILD_PROCESS",
            category=Category.CODE_EXECUTION,
            severity=Severity.HIGH,
            file_path="package/build/index.js",
            line_number=12,
            description="Detected child_process.exec() execution.",
            evidence="exec(",
            confidence=0.9,
        ),
        Finding(
            rule_id="JS_OBFUSCATION_ATTEMPT",
            category=Category.CODE_EXECUTION,
            severity=Severity.HIGH,
            file_path="package/build/index.js",
            line_number=42,
            description="Detected dense hex/unicode escape sequences consistent with obfuscation.",
            evidence="\\x61\\x62\\x63",
            confidence=0.9,
        ),
    ]
    verdict = SemanticVerdict(
        decision=SemanticDecision.ALLOW,
        confidence_score=0.61,
        explanation="This is a legitimate CLI utility that wraps local OS commands and does not decode hidden payloads, exfiltrate secrets, or bypass sandbox boundaries.",
        flagged_pattern="child_process wrapper in build output",
        decoded_malicious_payload=False,
    )

    engine = HybridEngine(_StubSemanticAnalyzer(verdict))
    result = engine.run(findings, context={})

    assert result["decision"] == "allow"
    assert result["risk_level"] == "MEDIUM"
    assert "[Semantic Override]" in result["explanation"]


def test_semantic_allow_does_not_override_critical_static_trigger():
    findings = [
        Finding(
            rule_id="JS_DYNAMIC_EVAL",
            category=Category.CODE_EXECUTION,
            severity=Severity.CRITICAL,
            file_path="index.js",
            line_number=1,
            description="Detected dynamic JavaScript execution via eval() or Function().",
            evidence="eval(",
            confidence=0.95,
        ),
    ]
    verdict = SemanticVerdict(
        decision=SemanticDecision.ALLOW,
        confidence_score=0.99,
        explanation="This looks intentional and controlled, but the static finding is still critical.",
        flagged_pattern="eval",
        decoded_malicious_payload=False,
    )

    engine = HybridEngine(_StubSemanticAnalyzer(verdict))
    result = engine.run(findings, context={})

    assert result["decision"] != "allow"
