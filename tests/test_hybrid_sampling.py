"""Tests for semantic batching: top trigger findings sampled for the LLM."""

from agentlens.engines.hybrid import (
    build_semantic_sample_summary,
    finding_text_for_injection_classifier,
    select_findings_for_semantic_llm,
    select_primary_finding,
    select_top_trigger_findings,
)
from agentlens.models.schema import Category, Finding, Severity


def _f(rule_id: str, sev: Severity, conf: float = 0.5, cat: Category = Category.CODE_EXECUTION):
    return Finding(
        rule_id=rule_id,
        category=cat,
        severity=sev,
        file_path=f"{rule_id}.py",
        line_number=1,
        description="x",
        evidence="x",
        confidence=conf,
    )


def test_select_top_prefers_distinct_rules():
    a = _f("RULE_A", Severity.CRITICAL, 0.9)
    b = _f("RULE_B", Severity.CRITICAL, 0.5)
    c = _f("RULE_A", Severity.HIGH, 0.99)
    out = select_top_trigger_findings([c, b, a], limit=3)
    # Strongest overall first (CRITICAL A), then other CRITICAL file/rule, then fill with HIGH A same file as first A
    assert out[0].rule_id == "RULE_A" and out[0].severity == Severity.CRITICAL
    assert out[1].rule_id == "RULE_B"
    assert out[2].rule_id == "RULE_A" and out[2].severity == Severity.HIGH
    assert len(out) == 3


def test_critical_second_file_before_high_other_rule():
    """Severity × confidence sort must not let a different rule at HIGH jump ahead of another CRITICAL hit."""
    x1 = Finding(
        rule_id="X",
        category=Category.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        file_path="f1.py",
        line_number=1,
        description="",
        evidence="",
        confidence=0.5,
    )
    y_high = Finding(
        rule_id="Y",
        category=Category.CODE_EXECUTION,
        severity=Severity.HIGH,
        file_path="f2.py",
        line_number=1,
        description="",
        evidence="",
        confidence=1.0,
    )
    x3 = Finding(
        rule_id="X",
        category=Category.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        file_path="f3.py",
        line_number=1,
        description="",
        evidence="",
        confidence=0.4,
    )
    out = select_top_trigger_findings([y_high, x3, x1], limit=3)
    assert [f.file_path for f in out] == ["f1.py", "f3.py", "f2.py"]
    assert out[2].rule_id == "Y"


def test_select_top_fills_when_few_rules():
    f1 = Finding(
        rule_id="SAME",
        category=Category.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        file_path="a.py",
        line_number=1,
        description="d",
        evidence="e1",
        confidence=0.9,
    )
    f2 = Finding(
        rule_id="SAME",
        category=Category.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        file_path="b.py",
        line_number=2,
        description="d",
        evidence="e2",
        confidence=0.8,
    )
    f3 = Finding(
        rule_id="SAME",
        category=Category.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        file_path="c.py",
        line_number=3,
        description="d",
        evidence="e3",
        confidence=0.7,
    )
    out = select_top_trigger_findings([f3, f1, f2], limit=3)
    assert len(out) == 3
    paths = {x.file_path for x in out}
    assert paths == {"a.py", "b.py", "c.py"}


def test_select_primary_is_first_of_batch():
    f1 = _f("A", Severity.HIGH, 0.5)
    f2 = _f("B", Severity.CRITICAL, 0.1)
    primary = select_primary_finding([f1, f2])
    assert primary is not None
    assert primary.rule_id == "B"


def test_build_semantic_sample_summary_counts():
    x1 = Finding(
        rule_id="X",
        category=Category.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        file_path="a.py",
        line_number=1,
        description="",
        evidence="",
        confidence=1.0,
    )
    x2 = Finding(
        rule_id="X",
        category=Category.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        file_path="a.py",
        line_number=2,
        description="",
        evidence="",
        confidence=0.9,
    )
    noise = Finding(
        rule_id="P",
        category=Category.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        file_path="r.md",
        line_number=1,
        description="",
        evidence="",
        confidence=1.0,
    )
    trigger = [f for f in [x1, x2, noise] if f.category in {Category.CODE_EXECUTION, Category.NETWORK_ACCESS}]
    sample = select_top_trigger_findings([x1, x2, noise], limit=3)
    summary = build_semantic_sample_summary(trigger, sample)
    assert summary.trigger_finding_count == 2
    assert summary.sent_finding_count == len(sample)
    assert summary.unique_file_count == 1
    assert len(summary.items) == len(sample)


class _FakeInjectionPrefilter:
    model_id = "test/prompt-injection"

    def __init__(self, scores):
        self._scores = scores

    def score_texts(self, texts):
        assert len(texts) == len(self._scores)
        return list(self._scores)


def test_select_findings_for_semantic_llm_prefilter_reorders():
    """Injection scores reorder which findings win the fixed semantic batch size."""
    findings = []
    for letter in "abcd":
        findings.append(
            Finding(
                rule_id="R",
                category=Category.CODE_EXECUTION,
                severity=Severity.CRITICAL,
                file_path=f"{letter}.py",
                line_number=1,
                description=letter,
                evidence=letter,
                confidence=0.5,
            )
        )
    scores = [0.1, 0.9, 0.2, 0.8]
    prefilter = _FakeInjectionPrefilter(scores)
    batch, inj_scores, model_id = select_findings_for_semantic_llm(
        findings,
        prefilter=prefilter,
        sample_size=3,
        pool_size=10,
    )
    assert [f.file_path for f in batch] == ["b.py", "d.py", "c.py"]
    assert inj_scores == [0.9, 0.8, 0.2]
    assert model_id == "test/prompt-injection"


def test_finding_text_for_injection_classifier_fallback():
    f = Finding(
        rule_id="X",
        category=Category.CODE_EXECUTION,
        severity=Severity.HIGH,
        file_path="only/path.py",
        line_number=1,
        description="",
        evidence=None,
        confidence=1.0,
    )
    assert "only/path.py" in finding_text_for_injection_classifier(f)


def test_non_trigger_excluded():
    net = Finding(
        rule_id="NET",
        category=Category.NETWORK_ACCESS,
        severity=Severity.CRITICAL,
        file_path="n.py",
        line_number=1,
        description="d",
        evidence="e",
        confidence=1.0,
    )
    inj = Finding(
        rule_id="INJ",
        category=Category.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        file_path="p.md",
        line_number=1,
        description="d",
        evidence="e",
        confidence=1.0,
    )
    out = select_top_trigger_findings([inj, net], limit=3)
    assert len(out) == 1
    assert out[0].rule_id == "NET"
