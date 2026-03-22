"""Tests for semantic batching: top trigger findings sampled for the LLM."""

from ai_guard.engines.hybrid import select_primary_finding, select_top_trigger_findings
from ai_guard.models.schema import Category, Finding, Severity


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
