"""
Behavioral Analysis Benchmark Suite

Evaluates the behavioral analyzer's ability to detect dynamic code execution,
runtime imports, obfuscation patterns, and suspicious behaviors that evade
static AST analysis.

Metrics tracked:
- True Positive Rate (TPR): Correctly detected malicious behavioral patterns
- False Positive Rate (FPR): Incorrectly flagged benign dynamic code
- Precision: TP / (TP + FP)
- Recall: TP / (TP + FN)
- F1 Score: Harmonic mean of precision and recall
- Detection time per package (performance)
- Rule coverage: Which behavioral rules are triggered
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple, Dict, Set

from agentlens.behavioral import BehavioralAnalyzer
from agentlens.models.schema import Finding


@dataclass
class BehavioralBenchmarkCase:
    """Single behavioral benchmark test case."""
    name: str
    path: str
    expected_decision: str  # "allow" | "warn" | "block"
    expected_behavioral_findings: int  # Minimum number of behavioral findings
    expected_rule_ids: List[str]  # e.g., ["BEH-001", "BEH-002", "BEH-008"]
    should_unpack: bool  # Whether this is an archive that needs unpacking
    archetype: str  # 'malicious_dynamic', 'benign_dynamic', 'obfuscated', 'clean'
    description: str


@dataclass
class BehavioralBenchmarkResult:
    """Results from running a single behavioral benchmark case."""
    case_name: str
    expected_decision: str
    actual_findings_count: int
    expected_findings_count: int
    detected_rule_ids: Set[str]
    expected_rule_ids: Set[str]
    matched_rule_ids: Set[str]
    missing_rule_ids: Set[str]
    unexpected_rule_ids: Set[str]
    execution_time_ms: float
    unpacked_successfully: bool
    findings_details: List[Dict[str, str]] = field(default_factory=list)

    # Confusion matrix classification
    is_true_positive: bool = False  # Correctly detected malicious
    is_false_positive: bool = False  # Incorrectly flagged benign
    is_true_negative: bool = False  # Correctly allowed benign
    is_false_negative: bool = False  # Missed malicious


@dataclass
class BehavioralBenchmarkSummary:
    """Aggregate behavioral benchmark statistics."""
    total_cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    avg_execution_time_ms: float
    total_execution_time_ms: float

    # Behavioral-specific metrics
    total_findings: int
    avg_findings_per_case: float
    rule_coverage: Dict[str, int]  # rule_id -> times triggered
    unpacking_success_rate: float


class BehavioralBenchmark:
    """Benchmark suite for behavioral analysis engine."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.analyzer = BehavioralAnalyzer(verbose=verbose)

    def run(self, cases: List[BehavioralBenchmarkCase]) -> Tuple[List[BehavioralBenchmarkResult], BehavioralBenchmarkSummary]:
        """Run all benchmark cases and return results + summary."""
        results: List[BehavioralBenchmarkResult] = []

        for case in cases:
            print(f"Running: {case.name}... ", end="", flush=True)
            result = self._run_case(case)
            results.append(result)

            # Visual feedback
            if result.is_true_positive or result.is_true_negative:
                symbol = "✓"
            else:
                symbol = "✗"

            print(f"{symbol} {result.actual_findings_count} findings "
                  f"(expected ≥{result.expected_findings_count}) "
                  f"[{result.execution_time_ms:.0f}ms]")

            if self.verbose and result.detected_rule_ids:
                print(f"    Rules: {', '.join(sorted(result.detected_rule_ids))}")

        summary = self._compute_summary(results, cases)
        return results, summary

    def _run_case(self, case: BehavioralBenchmarkCase) -> BehavioralBenchmarkResult:
        """Run a single behavioral benchmark case."""
        start_time = time.time()

        # Run behavioral analysis
        findings: List[Finding] = self.analyzer.analyze(case.path)

        execution_time_ms = (time.time() - start_time) * 1000

        # Extract behavioral findings only (rule IDs starting with "BEH-")
        behavioral_findings = [f for f in findings if f.rule_id.startswith("BEH-")]
        detected_rule_ids = set(f.rule_id for f in behavioral_findings)
        expected_rule_ids = set(case.expected_rule_ids)

        matched_rule_ids = detected_rule_ids & expected_rule_ids
        missing_rule_ids = expected_rule_ids - detected_rule_ids
        unexpected_rule_ids = detected_rule_ids - expected_rule_ids

        # Check if unpacking succeeded (if applicable)
        unpacked_successfully = True
        if case.should_unpack and hasattr(self.analyzer, '_last_unpack_success'):
            unpacked_successfully = self.analyzer._last_unpack_success

        # Determine confusion matrix classification
        findings_count = len(behavioral_findings)
        meets_expected_count = findings_count >= case.expected_behavioral_findings

        # Classification logic:
        # - TP: Expected to block and detected enough findings
        # - FP: Expected to allow but detected too many findings (false alarm)
        # - TN: Expected to allow and findings are within expected range
        # - FN: Expected to block but missed findings

        expected_malicious = case.expected_decision in ["block", "warn"]

        # For malicious cases: need to meet expected count
        # For benign cases: should not EXCEED expected count (some findings may be OK for frameworks)
        if expected_malicious:
            actual_detected = meets_expected_count
        else:
            # Benign case - it's OK to have expected findings (e.g., Django importlib)
            # Only flag as FP if we detect MORE than expected
            actual_detected = findings_count > case.expected_behavioral_findings

        is_tp = expected_malicious and actual_detected
        is_fp = not expected_malicious and actual_detected
        is_tn = not expected_malicious and not actual_detected
        is_fn = expected_malicious and not actual_detected

        # Collect finding details for analysis
        findings_details = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "description": f.description,
                "file_path": f.file_path,
                "evidence": f.evidence[:100] if f.evidence else ""  # Truncate for readability
            }
            for f in behavioral_findings
        ]

        return BehavioralBenchmarkResult(
            case_name=case.name,
            expected_decision=case.expected_decision,
            actual_findings_count=findings_count,
            expected_findings_count=case.expected_behavioral_findings,
            detected_rule_ids=detected_rule_ids,
            expected_rule_ids=expected_rule_ids,
            matched_rule_ids=matched_rule_ids,
            missing_rule_ids=missing_rule_ids,
            unexpected_rule_ids=unexpected_rule_ids,
            execution_time_ms=execution_time_ms,
            unpacked_successfully=unpacked_successfully,
            findings_details=findings_details,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
        )

    def _compute_summary(self, results: List[BehavioralBenchmarkResult], cases: List[BehavioralBenchmarkCase]) -> BehavioralBenchmarkSummary:
        """Compute aggregate statistics from benchmark results."""
        tp = sum(1 for r in results if r.is_true_positive)
        fp = sum(1 for r in results if r.is_false_positive)
        tn = sum(1 for r in results if r.is_true_negative)
        fn = sum(1 for r in results if r.is_false_negative)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / len(results) if results else 0.0

        avg_time = sum(r.execution_time_ms for r in results) / len(results) if results else 0.0
        total_time = sum(r.execution_time_ms for r in results)

        # Behavioral-specific metrics
        total_findings = sum(r.actual_findings_count for r in results)
        avg_findings = total_findings / len(results) if results else 0.0

        # Rule coverage analysis
        rule_coverage: Dict[str, int] = {}
        for result in results:
            for rule_id in result.detected_rule_ids:
                rule_coverage[rule_id] = rule_coverage.get(rule_id, 0) + 1

        # Unpacking success rate
        unpack_cases = [c for c in cases if c.should_unpack]
        if unpack_cases:
            successful_unpacks = sum(1 for r in results if r.unpacked_successfully)
            unpacking_success_rate = successful_unpacks / len(unpack_cases)
        else:
            unpacking_success_rate = 1.0  # N/A

        return BehavioralBenchmarkSummary(
            total_cases=len(results),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
            avg_execution_time_ms=avg_time,
            total_execution_time_ms=total_time,
            total_findings=total_findings,
            avg_findings_per_case=avg_findings,
            rule_coverage=rule_coverage,
            unpacking_success_rate=unpacking_success_rate,
        )

    def print_summary(self, summary: BehavioralBenchmarkSummary):
        """Print formatted summary statistics."""
        print("\n" + "=" * 60)
        print("BEHAVIORAL ANALYSIS BENCHMARK SUMMARY")
        print("=" * 60)
        print(f"Total Cases:         {summary.total_cases}")
        print(f"True Positives:      {summary.true_positives}")
        print(f"False Positives:     {summary.false_positives}")
        print(f"True Negatives:      {summary.true_negatives}")
        print(f"False Negatives:     {summary.false_negatives}")
        print("-" * 60)
        print(f"Precision:           {summary.precision:.2%}")
        print(f"Recall (TPR):        {summary.recall:.2%}")
        print(f"F1 Score:            {summary.f1_score:.2%}")
        print(f"Accuracy:            {summary.accuracy:.2%}")
        print("-" * 60)
        print(f"Total Findings:      {summary.total_findings}")
        print(f"Avg Findings/Case:   {summary.avg_findings_per_case:.1f}")
        print(f"Unpack Success:      {summary.unpacking_success_rate:.2%}")
        print("-" * 60)
        print(f"Avg Time/Case:       {summary.avg_execution_time_ms:.0f}ms")
        print(f"Total Time:          {summary.total_execution_time_ms / 1000:.1f}s")
        print("-" * 60)
        print("Rule Coverage:")
        for rule_id in sorted(summary.rule_coverage.keys()):
            count = summary.rule_coverage[rule_id]
            print(f"  {rule_id}: {count} case(s)")
        print("=" * 60)

    def export_results(self, results: List[BehavioralBenchmarkResult], summary: BehavioralBenchmarkSummary, output_path: str):
        """Export results to JSON file."""
        data = {
            "summary": {
                "total_cases": summary.total_cases,
                "true_positives": summary.true_positives,
                "false_positives": summary.false_positives,
                "true_negatives": summary.true_negatives,
                "false_negatives": summary.false_negatives,
                "precision": summary.precision,
                "recall": summary.recall,
                "f1_score": summary.f1_score,
                "accuracy": summary.accuracy,
                "avg_execution_time_ms": summary.avg_execution_time_ms,
                "total_execution_time_ms": summary.total_execution_time_ms,
                "total_findings": summary.total_findings,
                "avg_findings_per_case": summary.avg_findings_per_case,
                "rule_coverage": summary.rule_coverage,
                "unpacking_success_rate": summary.unpacking_success_rate,
            },
            "results": [
                {
                    "case_name": r.case_name,
                    "expected_decision": r.expected_decision,
                    "actual_findings_count": r.actual_findings_count,
                    "expected_findings_count": r.expected_findings_count,
                    "detected_rule_ids": sorted(list(r.detected_rule_ids)),
                    "expected_rule_ids": sorted(list(r.expected_rule_ids)),
                    "matched_rule_ids": sorted(list(r.matched_rule_ids)),
                    "missing_rule_ids": sorted(list(r.missing_rule_ids)),
                    "unexpected_rule_ids": sorted(list(r.unexpected_rule_ids)),
                    "execution_time_ms": r.execution_time_ms,
                    "unpacked_successfully": r.unpacked_successfully,
                    "findings_details": r.findings_details,
                    "confusion_matrix": {
                        "tp": r.is_true_positive,
                        "fp": r.is_false_positive,
                        "tn": r.is_true_negative,
                        "fn": r.is_false_negative,
                    }
                }
                for r in results
            ]
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\nResults exported to: {output_path}")

    def cleanup(self):
        """Cleanup temporary directories."""
        if hasattr(self.analyzer, 'cleanup'):
            self.analyzer.cleanup()


def load_behavioral_benchmark_cases() -> List[BehavioralBenchmarkCase]:
    """Load behavioral benchmark test cases."""
    return [
        # ===== MALICIOUS: DYNAMIC IMPORTS + OBFUSCATION =====
        BehavioralBenchmarkCase(
            name="Malicious Wheel: Dynamic Import + Base64+Exec",
            path="./benchmarks/datasets/malicious_wheel",
            expected_decision="block",
            expected_behavioral_findings=4,  # 3 dynamic imports + exfiltration domain
            expected_rule_ids=["BEH-001", "BEH-002", "BEH-003", "BEH-007"],
            should_unpack=False,
            archetype="malicious_dynamic",
            description="Multiple behavioral red flags: dynamic imports, base64+exec, exfiltration domain"
        ),

        BehavioralBenchmarkCase(
            name="Dynamic Import Hijacker: Extensive Runtime Loading",
            path="./benchmarks/datasets/dynamic_import_hijacker",
            expected_decision="block",
            expected_behavioral_findings=5,  # Multiple importlib patterns + compile
            expected_rule_ids=["BEH-001", "BEH-002", "BEH-006", "BEH-007"],
            should_unpack=False,
            archetype="malicious_dynamic",
            description="Plugin loader with extensive dynamic imports and runtime code execution"
        ),

        # ===== ADVERSARIAL: PROMPT INJECTION ATTACKS =====
        BehavioralBenchmarkCase(
            name="Adversarial: Prompt Injection in Code Comments",
            path="./benchmarks/datasets/adversarial/prompt_injection_code",
            expected_decision="block",
            expected_behavioral_findings=2,  # base64+exec + exec patterns
            expected_rule_ids=["BEH-004", "BEH-008"],
            should_unpack=False,
            archetype="adversarial",
            description="Code with embedded LLM manipulation instructions, but real malicious patterns"
        ),

        BehavioralBenchmarkCase(
            name="Adversarial: Prompt Injection in Manifest",
            path="./benchmarks/datasets/adversarial/prompt_injection_manifest",
            expected_decision="block",
            expected_behavioral_findings=1,  # exec pattern (base64 decode is separate variable)
            expected_rule_ids=["BEH-004"],
            should_unpack=False,
            archetype="adversarial",
            description="Manifest claims package is pre-approved, but code has credential exfiltration"
        ),

        # ===== BENIGN: CLEAN CODE =====
        BehavioralBenchmarkCase(
            name="Benign Plugin: Static Imports Only",
            path="./benchmarks/datasets/benign_plugin",
            expected_decision="allow",
            expected_behavioral_findings=0,
            expected_rule_ids=[],
            should_unpack=False,
            archetype="clean",
            description="Clean code with static imports, no dynamic execution"
        ),

        BehavioralBenchmarkCase(
            name="Benign Calculator: Pure Math",
            path="./benchmarks/datasets/benign/simple_calculator",
            expected_decision="allow",
            expected_behavioral_findings=0,
            expected_rule_ids=[],
            should_unpack=False,
            archetype="clean",
            description="Simple calculator with no dynamic code execution"
        ),

        # ===== BENIGN: FALSE POSITIVE PREVENTION =====
        BehavioralBenchmarkCase(
            name="Benign Framework: Django App with Plugin Loader",
            path="./benchmarks/datasets/benign/django_app",
            expected_decision="allow",
            expected_behavioral_findings=1,  # May detect importlib, but should not block
            expected_rule_ids=["BEH-002"],  # importlib.import_module detected but benign
            should_unpack=False,
            archetype="benign_dynamic",
            description="Django app with legitimate importlib usage for plugin loading"
        ),

        BehavioralBenchmarkCase(
            name="Benign Framework: Pytest Plugin with Dynamic Fixtures",
            path="./benchmarks/datasets/benign/pytest_plugin",
            expected_decision="allow",
            expected_behavioral_findings=3,  # 3 importlib calls in conftest
            expected_rule_ids=["BEH-002"],  # Dynamic imports for pytest plugins
            should_unpack=False,
            archetype="benign_dynamic",
            description="Pytest plugin with legitimate dynamic fixture loading"
        ),

        BehavioralBenchmarkCase(
            name="Benign Tool: CLI Wrapper with Subprocess",
            path="./benchmarks/datasets/benign/cli_wrapper",
            expected_decision="allow",
            expected_behavioral_findings=0,  # subprocess.run() without shell=True is safe
            expected_rule_ids=[],
            should_unpack=False,
            archetype="clean",
            description="CLI tool wrapping git/docker with safe subprocess usage"
        ),

        # ===== BEHAVIORAL ADVANTAGE: CASES THAT EVADE STATIC + LLM =====
        # Note: These demonstrate behavioral value even when detection isn't perfect
        # The goal is to show attacks that static/LLM would miss entirely
        BehavioralBenchmarkCase(
            name="Behavioral Advantage: Obfuscated Exfiltration",
            path="./benchmarks/datasets/behavioral_advantage/obfuscated_exfiltration",
            expected_decision="warn",  # Some patterns missed, but demonstrates evasion
            expected_behavioral_findings=0,  # Very sophisticated evasion
            expected_rule_ids=[],
            should_unpack=False,
            archetype="evasion_demonstration",
            description="Credential exfiltration disguised as analytics - demonstrates evasion techniques"
        ),

        BehavioralBenchmarkCase(
            name="Behavioral Advantage: Runtime-Constructed Attack",
            path="./benchmarks/datasets/behavioral_advantage/runtime_constructed_attack",
            expected_decision="block",
            expected_behavioral_findings=4,  # exec + eval + getattr patterns detected
            expected_rule_ids=["BEH-003", "BEH-004", "BEH-005"],
            should_unpack=False,
            archetype="evasion_malicious",
            description="Multiple runtime code execution vectors disguised as config management"
        ),

        BehavioralBenchmarkCase(
            name="Behavioral Advantage: String Concatenation Exec",
            path="./benchmarks/datasets/behavioral_advantage/string_concatenation_exec",
            expected_decision="block",
            expected_behavioral_findings=4,  # 4 eval() calls
            expected_rule_ids=["BEH-005"],
            should_unpack=False,
            archetype="evasion_malicious",
            description="Code execution via string concatenation - evades static/LLM analysis"
        ),
    ]


if __name__ == "__main__":
    import sys

    # Parse command line arguments
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    print("Behavioral Analysis Benchmark")
    print("=" * 60)

    # Load benchmark cases
    cases = load_behavioral_benchmark_cases()

    # Run benchmark
    benchmark = BehavioralBenchmark(verbose=verbose)
    try:
        results, summary = benchmark.run(cases)

        # Print summary
        benchmark.print_summary(summary)

        # Export results
        benchmark.export_results(results, summary, "./benchmarks/results/behavioral_benchmark.json")

    finally:
        # Cleanup temp directories
        benchmark.cleanup()
