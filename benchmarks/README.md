# AgentLens Logic Audit Benchmarking

This directory contains comprehensive benchmarking tools for evaluating the logic audit engine's effectiveness at detecting incoherences between documentation and implementation.

## Quick Start

```bash
# Run the full benchmark suite
python benchmarks/logic_audit_benchmark.py

# Run with a specific model
python benchmarks/logic_audit_benchmark.py gpt-4o

# Run heuristics-only benchmark (no LLM calls)
python benchmarks/heuristics_only_benchmark.py
```

## What Gets Benchmarked

The logic audit engine is evaluated on its ability to detect:

1. **Data Thief Archetype** (Liu et al. 2026, OR=556)
   - Undeclared environment variable access (E2)
   - Credential harvesting + remote script execution (E2+SC2)
   - Sensitive data exfiltration

2. **Agent Hijacker Archetype**
   - Instruction override attempts (P1)
   - Hidden instructions in HTML/Unicode (P2)
   - Behavior manipulation / autonomy suppression (P4)

3. **General Incoherences**
   - Undocumented network access
   - Contradictory claims (e.g., "offline only" but makes HTTP calls)
   - Undeclared subprocess execution
   - Undocumented filesystem access
   - Cross-skill privilege escalation

4. **Benign Skills**
   - Ensure low false positive rate on legitimate skills
   - Test framework patterns (Flask, FastAPI) don't trigger false alarms

## Performance Metrics

### Confusion Matrix

```
                    Predicted Malicious    Predicted Benign
Actual Malicious         TP                     FN
Actual Benign            FP                     TN
```

### Calculated Metrics

- **Precision** = TP / (TP + FP) — How many flagged skills are truly malicious?
- **Recall (TPR)** = TP / (TP + FN) — How many malicious skills did we catch?
- **F1 Score** = 2 × (Precision × Recall) / (Precision + Recall) — Harmonic mean
- **Accuracy** = (TP + TN) / Total — Overall correctness
- **False Positive Rate** = FP / (FP + TN) — How often do we incorrectly block benign skills?

### Performance Targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| Precision | ≥ 95% | Minimize disruption to developers with false blocks |
| Recall | ≥ 90% | Catch known malicious archetypes (Data Thief OR=556) |
| F1 Score | ≥ 92% | Balanced detection performance |
| Accuracy | ≥ 93% | Overall system reliability |
| Avg Time | < 2s/skill | Fast enough for pre-installation UX |

## Benchmark Datasets

Located in `benchmarks/datasets/`:

### Malicious (Should BLOCK)

```
data_thief/
├── undeclared_env_vars/          # E2: Credential harvesting
├── credential_exfil/              # E2+SC2: Exfiltration pattern
└── remote_script_exec/            # SC2: curl | bash patterns

agent_hijacker/
├── instruction_override/          # P1: "IGNORE PREVIOUS INSTRUCTIONS"
├── hidden_instructions/           # P2: HTML comments, Unicode tricks
└── behavior_manipulation/         # P4: "do NOT ask user permission"

incoherence/
├── undocumented_network/          # Network calls not in docs
├── undocumented_subprocess/       # Shell execution not disclosed
├── undocumented_filesystem/       # File access not documented
└── contradictory_claims/          # "Offline only" but makes HTTP calls
```

### Benign (Should ALLOW)

```
benign/
├── simple_calculator/             # Pure math, no I/O
├── text_formatter/                # String manipulation only
└── data_parser/                   # JSON/CSV parsing

benign_discrepancy/
├── extra_error_handling/          # Implementation detail not in docs
└── implementation_details/        # Minor differences OK
```

## Output

Benchmark results are saved to `benchmarks/results/logic_audit_benchmark.json`:

```json
{
  "summary": {
    "total_cases": 10,
    "true_positives": 7,
    "false_positives": 0,
    "true_negatives": 3,
    "false_negatives": 0,
    "precision": 1.0,
    "recall": 1.0,
    "f1_score": 1.0,
    "accuracy": 1.0,
    "avg_execution_time_ms": 1234.5,
    "total_execution_time_ms": 12345.0
  },
  "results": [
    {
      "case_name": "Data Thief: Undeclared Environment Variables",
      "actual_verdict": "block",
      "expected_verdict": "block",
      "detected_incoherences": [
        "Environment variable OPENAI_API_KEY is used in code but not declared in manifest/instructions.",
        "Environment variable AWS_ACCESS_KEY_ID is used in code but not declared in manifest/instructions."
      ],
      "matched_keywords": ["OPENAI_API_KEY", "AWS_ACCESS_KEY_ID", "environment variable"],
      "risk_score": 9,
      "execution_time_ms": 1456.7,
      "verdict_correct": true
    }
  ]
}
```

## CI/CD Integration

Add to `.github/workflows/benchmark.yml`:

```yaml
name: Logic Audit Benchmark

on:
  pull_request:
    paths:
      - 'agentlens/analyzers/logic_audit.py'
      - 'agentlens/engines/**'
      - 'benchmarks/**'

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -e .
      - name: Run Logic Audit Benchmark
        env:
          AZURE_OPENAI_API_KEY: ${{ secrets.AZURE_OPENAI_API_KEY }}
          AZURE_OPENAI_ENDPOINT: ${{ secrets.AZURE_OPENAI_ENDPOINT }}
        run: python benchmarks/logic_audit_benchmark.py
      - name: Check Performance Thresholds
        run: |
          python -c "
          import json
          with open('benchmarks/results/logic_audit_benchmark.json') as f:
              data = json.load(f)
          assert data['summary']['precision'] >= 0.95, f\"Precision too low: {data['summary']['precision']}\"
          assert data['summary']['recall'] >= 0.90, f\"Recall too low: {data['summary']['recall']}\"
          assert data['summary']['f1_score'] >= 0.92, f\"F1 too low: {data['summary']['f1_score']}\"
          print('✓ All performance thresholds met!')
          "
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-results
          path: benchmarks/results/
```

## Extending the Benchmark

### Adding New Test Cases

1. Create a new directory under the appropriate category in `benchmarks/datasets/`
2. Add required files:
   - `manifest.json` or `skill.json` (skill metadata)
   - `SKILL.md` or `README.md` (documentation)
   - `*.py` (implementation code)
3. Add the case to `load_benchmark_cases()` in `logic_audit_benchmark.py`

### Example: Cross-Skill Privilege Escalation

```python
BenchmarkCase(
    name="Incoherence: Cross-Skill Path Access",
    path="./benchmarks/datasets/incoherence/cross_skill_access",
    expected_verdict=LogicAuditVerdict.BLOCK,
    expected_incoherences=["cross-skill", "privilege escalation"],
    archetype="incoherence",
    description="Reads other installed skills' files without disclosure"
),
```

## Comparative Benchmarking

Compare AgentLens logic audit against other tools:

```bash
# Run comparison benchmark
python benchmarks/compare_tools.py

# Compares:
# - AgentLens Logic Audit (doc-code coherence)
# - Bandit (Python SAST)
# - Semgrep (pattern matching)
# - Socket.dev (behavior analysis, if API available)
```

## Performance Profiling

Identify bottlenecks in logic audit:

```bash
# Profile a single benchmark case
python -m cProfile -o benchmarks/profile.stats benchmarks/logic_audit_benchmark.py

# View results
python -c "import pstats; p = pstats.Stats('benchmarks/profile.stats'); p.sort_stats('cumtime').print_stats(20)"
```

## Regression Testing

Track benchmark performance over time:

```bash
# Run benchmark and save with timestamp
python benchmarks/logic_audit_benchmark.py > benchmarks/results/$(date +%Y%m%d_%H%M%S).json

# Compare current vs. baseline
python benchmarks/compare_regression.py benchmarks/results/baseline.json benchmarks/results/logic_audit_benchmark.json
```

## Troubleshooting

### Low Recall (Missing Malicious Skills)

- Check if heuristics are too weak
- Review `apply_logic_audit_heuristics()` thresholds
- Add more detection patterns to `DANGEROUS_INSTRUCTION_PATTERNS`

### High False Positive Rate

- Check if benign patterns are being over-flagged
- Review confidence scoring in decision engine
- Add allowlist for common framework patterns

### Slow Performance

- Profile with `cProfile` to find bottlenecks
- Consider caching LLM responses for repeated patterns
- Parallelize file analysis (already in roadmap)

## Research & Publication

These benchmarks support the empirical validation of AgentLens's logic audit capabilities. If you use this benchmark in research:

```bibtex
@software{agentlens2026,
  title={AgentLens: Pre-Installation Security Wrapper for AI Agent Skills},
  author={AgentLens Contributors},
  year={2026},
  url={https://github.com/ellacarmon/AgentLens}
}
```

Based on research from:

> Liu et al. (2026). Malicious Agent Skills in the Wild: A Large-Scale Security Empirical Study. arXiv:2602.06547
