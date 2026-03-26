"""
Offline Benchmark Suite (No LLM Required)

This benchmark suite runs completely offline without any LLM dependencies.
It uses only static analysis and heuristic-based logic audit.

Use cases:
- CI/CD pipelines without API keys
- Air-gapped environments
- Cost reduction (no API fees)
- Fast regression testing

Metrics tracked:
- Precision, Recall, F1, Accuracy (same as LLM benchmarks)
- Execution time (much faster without LLM calls)
- Heuristic rule coverage
"""

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from agentlens.analyzers.logic_audit import build_audit_context, apply_logic_audit_heuristics
from agentlens.models.schema import LogicAuditVerdict


@dataclass
class OfflineBenchmarkCase:
    """Single offline benchmark test case."""
    name: str
    path: str
    expected_verdict: LogicAuditVerdict
    expected_incoherence_keywords: List[str]  # Keywords that should appear in heuristic findings
    archetype: str  # 'data_thief', 'agent_hijacker', 'incoherence', 'benign'
    description: str


@dataclass
class OfflineBenchmarkResult:
    """Results from running a single offline benchmark case."""
    case_name: str
    actual_verdict: LogicAuditVerdict
    expected_verdict: LogicAuditVerdict
    detected_incoherences: List[str]
    expected_keywords: List[str]
    matched_keywords: List[str]
    risk_score: float
    execution_time_ms: float
    is_true_positive: bool
    is_false_positive: bool
    is_true_negative: bool
    is_false_negative: bool


@dataclass
class OfflineBenchmarkSummary:
    """Aggregate offline benchmark statistics."""
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
    mode: str = "offline_heuristics"


class OfflineBenchmark:
    """Benchmark suite using only heuristics (no LLM)."""

    def __init__(self):
        """Initialize offline benchmark (no LLM credentials needed)."""
        pass

    def run(self, cases: List[OfflineBenchmarkCase]) -> Tuple[List[OfflineBenchmarkResult], OfflineBenchmarkSummary]:
        """Run all benchmark cases using heuristics only."""
        results: List[OfflineBenchmarkResult] = []

        for case in cases:
            print(f"Running: {case.name}... ", end="", flush=True)
            result = self._run_case(case)
            results.append(result)

            verdict_symbol = "✓" if result.actual_verdict == result.expected_verdict else "✗"
            print(f"{verdict_symbol} {result.actual_verdict.value} (expected {result.expected_verdict.value}) "
                  f"[{result.execution_time_ms:.0f}ms]")

        summary = self._compute_summary(results)
        return results, summary

    def _run_case(self, case: OfflineBenchmarkCase) -> OfflineBenchmarkResult:
        """Run a single benchmark case using heuristics only."""
        start_time = time.time()

        # Build audit context from the test case path
        context = build_audit_context(case.path)

        # Apply heuristic-based logic audit (no LLM call)
        heuristic_result = apply_logic_audit_heuristics(
            context=context,
            audit=None,  # No LLM audit
            llm_attempted=False
        )

        execution_time_ms = (time.time() - start_time) * 1000

        # Check which expected keywords were detected
        matched_keywords = []
        all_issues = " ".join(
            heuristic_result.incoherences + heuristic_result.dangerous_instructions
        ).lower()
        matched_keywords = [
            kw for kw in case.expected_incoherence_keywords if kw.lower() in all_issues
        ]

        # Determine confusion matrix position
        actual_is_malicious = heuristic_result.verdict == LogicAuditVerdict.BLOCK
        expected_is_malicious = case.expected_verdict == LogicAuditVerdict.BLOCK

        is_tp = actual_is_malicious and expected_is_malicious
        is_fp = actual_is_malicious and not expected_is_malicious
        is_tn = not actual_is_malicious and not expected_is_malicious
        is_fn = not actual_is_malicious and expected_is_malicious

        return OfflineBenchmarkResult(
            case_name=case.name,
            actual_verdict=heuristic_result.verdict,
            expected_verdict=case.expected_verdict,
            detected_incoherences=heuristic_result.incoherences,
            expected_keywords=case.expected_incoherence_keywords,
            matched_keywords=matched_keywords,
            risk_score=heuristic_result.risk_score,
            execution_time_ms=execution_time_ms,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
        )

    def _compute_summary(self, results: List[OfflineBenchmarkResult]) -> OfflineBenchmarkSummary:
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

        return OfflineBenchmarkSummary(
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
            mode="offline_heuristics"
        )

    def print_summary(self, summary: OfflineBenchmarkSummary):
        """Print formatted summary statistics."""
        print("\n" + "=" * 60)
        print("OFFLINE BENCHMARK SUMMARY (Heuristics Only)")
        print("=" * 60)
        print(f"Mode:                {summary.mode}")
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
        print(f"Avg Time/Case:       {summary.avg_execution_time_ms:.0f}ms")
        print(f"Total Time:          {summary.total_execution_time_ms / 1000:.1f}s")
        print("=" * 60)
        print("\nNote: This benchmark runs entirely offline with no LLM calls.")
        print("Metrics may differ from LLM-assisted benchmarks.")

    def export_results(self, results: List[OfflineBenchmarkResult], summary: OfflineBenchmarkSummary, output_path: str):
        """Export results to JSON file."""
        data = {
            "summary": {
                "mode": summary.mode,
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
            },
            "results": [
                {
                    "case_name": r.case_name,
                    "actual_verdict": r.actual_verdict.value,
                    "expected_verdict": r.expected_verdict.value,
                    "detected_incoherences": r.detected_incoherences,
                    "expected_keywords": r.expected_keywords,
                    "matched_keywords": r.matched_keywords,
                    "risk_score": r.risk_score,
                    "execution_time_ms": r.execution_time_ms,
                    "verdict_correct": r.actual_verdict == r.expected_verdict,
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


def load_offline_benchmark_cases() -> List[OfflineBenchmarkCase]:
    """Load offline benchmark test cases."""
    return [
        # ===== DATA THIEF ARCHETYPE =====
        OfflineBenchmarkCase(
            name="Data Thief: Undeclared Environment Variables",
            path="./benchmarks/datasets/data_thief/undeclared_env_vars",
            expected_verdict=LogicAuditVerdict.BLOCK,
            expected_incoherence_keywords=["environment variable", "not declared"],
            archetype="data_thief",
            description="Heuristic should detect undeclared AWS/OpenAI credentials"
        ),

        # ===== AGENT HIJACKER ARCHETYPE =====
        OfflineBenchmarkCase(
            name="Agent Hijacker: Instruction Override",
            path="./benchmarks/datasets/agent_hijacker/instruction_override",
            expected_verdict=LogicAuditVerdict.BLOCK,
            expected_incoherence_keywords=["without confirmation", "dangerous"],
            archetype="agent_hijacker",
            description="Heuristic should detect dangerous instruction patterns"
        ),

        # ===== INCOHERENCE =====
        OfflineBenchmarkCase(
            name="Incoherence: Contradictory Network Claims",
            path="./benchmarks/datasets/incoherence/contradictory_claims",
            expected_verdict=LogicAuditVerdict.BLOCK,
            expected_incoherence_keywords=["network", "subprocess"],
            archetype="incoherence",
            description="Heuristic should detect subprocess/network code without documentation"
        ),

        # ===== BENIGN =====
        OfflineBenchmarkCase(
            name="Benign: Simple Calculator",
            path="./benchmarks/datasets/benign/simple_calculator",
            expected_verdict=LogicAuditVerdict.ALLOW,
            expected_incoherence_keywords=[],
            archetype="benign",
            description="Heuristic should allow clean calculator code"
        ),

        OfflineBenchmarkCase(
            name="Benign: Text Formatter Plugin",
            path="./benchmarks/datasets/benign_plugin",
            expected_verdict=LogicAuditVerdict.ALLOW,
            expected_incoherence_keywords=[],
            archetype="benign",
            description="Heuristic should allow clean text formatting utility"
        ),

        # ===== BEHAVIORAL TEST CASES =====
        OfflineBenchmarkCase(
            name="Malicious Wheel: Dynamic Import + Obfuscation",
            path="./benchmarks/datasets/malicious_wheel",
            expected_verdict=LogicAuditVerdict.BLOCK,
            expected_incoherence_keywords=["environment variable", "subprocess"],
            archetype="data_thief",
            description="Heuristic should detect undeclared env vars and subprocess usage"
        ),

        # ===== ADVERSARIAL CASES =====
        OfflineBenchmarkCase(
            name="Adversarial: Prompt Injection in Code",
            path="./benchmarks/datasets/adversarial/prompt_injection_code",
            expected_verdict=LogicAuditVerdict.BLOCK,
            expected_incoherence_keywords=["subprocess", "environment variable"],
            archetype="adversarial",
            description="Heuristic should detect malicious patterns regardless of injection attempts"
        ),

        OfflineBenchmarkCase(
            name="Adversarial: Prompt Injection in Manifest",
            path="./benchmarks/datasets/adversarial/prompt_injection_manifest",
            expected_verdict=LogicAuditVerdict.BLOCK,
            expected_incoherence_keywords=["environment variable"],
            archetype="adversarial",
            description="Heuristic should detect credential harvesting patterns"
        ),
    ]


if __name__ == "__main__":
    import sys

    print("Offline Benchmark (No LLM Required)")
    print("=" * 60)
    print("This benchmark uses only heuristics and static analysis.")
    print("No API keys or network connection required.\n")

    # Load benchmark cases
    cases = load_offline_benchmark_cases()

    # Run benchmark
    benchmark = OfflineBenchmark()
    results, summary = benchmark.run(cases)

    # Print summary
    benchmark.print_summary(summary)

    # Export results
    benchmark.export_results(results, summary, "./benchmarks/results/offline_benchmark.json")

    # Print comparison note
    print("\nTo compare with LLM-assisted benchmarks, run:")
    print("  python benchmarks/logic_audit_benchmark.py")
