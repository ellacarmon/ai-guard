"""
Benchmark Regression Comparison Tool

Compares current benchmark results against a baseline to detect regressions
in logic audit performance.
"""

import json
import sys
from pathlib import Path


def load_results(path: str) -> dict:
    """Load benchmark results from JSON file."""
    with open(path, 'r') as f:
        return json.load(f)


def compare_results(baseline: dict, current: dict):
    """Compare current results against baseline and report regressions."""
    print("=" * 70)
    print("LOGIC AUDIT BENCHMARK REGRESSION ANALYSIS")
    print("=" * 70)
    print("")

    baseline_summary = baseline['summary']
    current_summary = current['summary']

    # Key metrics to track
    metrics = ['precision', 'recall', 'f1_score', 'accuracy']

    print("Metric Comparison:")
    print("-" * 70)
    print(f"{'Metric':<15} {'Baseline':>10} {'Current':>10} {'Change':>10} {'Status':>10}")
    print("-" * 70)

    regressions = []
    improvements = []

    for metric in metrics:
        baseline_val = baseline_summary[metric]
        current_val = current_summary[metric]
        change = current_val - baseline_val
        change_pct = (change / baseline_val * 100) if baseline_val > 0 else 0

        # Determine status
        if abs(change) < 0.01:  # Within 1%
            status = "="
        elif change > 0:
            status = "↑"
            improvements.append((metric, change_pct))
        else:
            status = "↓"
            regressions.append((metric, change_pct))

        print(f"{metric.capitalize():<15} {baseline_val:>9.1%} {current_val:>9.1%} "
              f"{change:>+9.1%} {status:>10}")

    print("-" * 70)

    # Performance comparison
    baseline_time = baseline_summary['avg_execution_time_ms']
    current_time = current_summary['avg_execution_time_ms']
    time_change = current_time - baseline_time
    time_change_pct = (time_change / baseline_time * 100) if baseline_time > 0 else 0

    print(f"\nPerformance:")
    print(f"  Baseline avg time: {baseline_time:.0f}ms")
    print(f"  Current avg time:  {current_time:.0f}ms")
    print(f"  Change:            {time_change:+.0f}ms ({time_change_pct:+.1f}%)")

    # Detailed case-by-case comparison
    print("\n" + "=" * 70)
    print("CASE-BY-CASE ANALYSIS")
    print("=" * 70)

    baseline_results = {r['case_name']: r for r in baseline['results']}
    current_results = {r['case_name']: r for r in current['results']}

    all_cases = set(baseline_results.keys()) | set(current_results.keys())

    new_failures = []
    new_passes = []

    for case_name in sorted(all_cases):
        baseline_case = baseline_results.get(case_name)
        current_case = current_results.get(case_name)

        if baseline_case is None:
            print(f"\n[NEW] {case_name}")
            if current_case['verdict_correct']:
                print(f"  ✓ PASS")
            else:
                print(f"  ✗ FAIL")
                new_failures.append(case_name)
            continue

        if current_case is None:
            print(f"\n[REMOVED] {case_name}")
            continue

        baseline_correct = baseline_case['verdict_correct']
        current_correct = current_case['verdict_correct']

        if baseline_correct and not current_correct:
            print(f"\n[REGRESSION] {case_name}")
            print(f"  Baseline: ✓ {baseline_case['actual_verdict']} (correct)")
            print(f"  Current:  ✗ {current_case['actual_verdict']} (expected {current_case['expected_verdict']})")
            new_failures.append(case_name)
        elif not baseline_correct and current_correct:
            print(f"\n[FIXED] {case_name}")
            print(f"  Baseline: ✗ {baseline_case['actual_verdict']} (expected {baseline_case['expected_verdict']})")
            print(f"  Current:  ✓ {current_case['actual_verdict']} (correct)")
            new_passes.append(case_name)
        elif not baseline_correct and not current_correct:
            print(f"\n[STILL FAILING] {case_name}")
            print(f"  Expected: {current_case['expected_verdict']}")
            print(f"  Got:      {current_case['actual_verdict']}")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    if regressions:
        print(f"\n⚠️  {len(regressions)} metric regression(s):")
        for metric, change_pct in regressions:
            print(f"   - {metric}: {change_pct:+.1f}%")

    if improvements:
        print(f"\n✓ {len(improvements)} metric improvement(s):")
        for metric, change_pct in improvements:
            print(f"   - {metric}: {change_pct:+.1f}%")

    if new_failures:
        print(f"\n✗ {len(new_failures)} new or regressed case(s):")
        for case in new_failures:
            print(f"   - {case}")

    if new_passes:
        print(f"\n✓ {len(new_passes)} fixed case(s):")
        for case in new_passes:
            print(f"   - {case}")

    # Exit code determination
    exit_code = 0

    # Fail if precision/recall dropped more than 5%
    for metric in ['precision', 'recall']:
        baseline_val = baseline_summary[metric]
        current_val = current_summary[metric]
        if current_val < baseline_val - 0.05:
            print(f"\n❌ CRITICAL: {metric} dropped by more than 5%")
            exit_code = 1

    # Fail if new failures introduced
    if new_failures:
        print(f"\n❌ CRITICAL: {len(new_failures)} test case(s) regressed or failed")
        exit_code = 1

    if exit_code == 0:
        print("\n✅ No significant regressions detected")
    else:
        print("\n❌ Regressions detected - review changes before merging")

    return exit_code


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python compare_regression.py <baseline.json> <current.json>")
        sys.exit(1)

    baseline_path = sys.argv[1]
    current_path = sys.argv[2]

    if not Path(baseline_path).exists():
        print(f"Error: Baseline file not found: {baseline_path}")
        sys.exit(1)

    if not Path(current_path).exists():
        print(f"Error: Current file not found: {current_path}")
        sys.exit(1)

    baseline = load_results(baseline_path)
    current = load_results(current_path)

    exit_code = compare_results(baseline, current)
    sys.exit(exit_code)
