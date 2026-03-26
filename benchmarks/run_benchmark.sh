#!/bin/bash
set -e

echo "=========================================="
echo "AgentLens Logic Audit Benchmark Suite"
echo "=========================================="
echo ""

# Check environment variables
if [ -z "$AZURE_OPENAI_API_KEY" ] || [ -z "$AZURE_OPENAI_ENDPOINT" ]; then
    echo "⚠️  Warning: Azure OpenAI credentials not set"
    echo "   Logic audit will run heuristics-only mode"
    echo "   Set AZURE_OPENAI_API_KEY and AZURE_OPENAI_ENDPOINT for full LLM-enhanced auditing"
    echo ""
fi

# Create results directory
mkdir -p benchmarks/results

# Run benchmark
echo "Running benchmark..."
python benchmarks/logic_audit_benchmark.py "${1:-gpt-5-mini}"

# Check if results meet thresholds
echo ""
echo "Checking performance thresholds..."
python -c "
import json
import sys

with open('benchmarks/results/logic_audit_benchmark.json') as f:
    data = json.load(f)

summary = data['summary']
passed = True

# Define thresholds
thresholds = {
    'precision': 0.95,
    'recall': 0.90,
    'f1_score': 0.92,
    'accuracy': 0.93
}

print('Performance Check:')
print('-' * 50)
for metric, threshold in thresholds.items():
    actual = summary[metric]
    status = '✓' if actual >= threshold else '✗'
    print(f'{status} {metric.capitalize():12} {actual:.2%} (threshold: {threshold:.0%})')
    if actual < threshold:
        passed = False

print('-' * 50)

if passed:
    print('✓ All performance thresholds met!')
    sys.exit(0)
else:
    print('✗ Some thresholds not met. Review benchmark results.')
    sys.exit(1)
"

echo ""
echo "Results saved to: benchmarks/results/logic_audit_benchmark.json"
