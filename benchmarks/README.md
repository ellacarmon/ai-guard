# AgentLens Benchmark Suite

Comprehensive benchmark system for evaluating AgentLens security analysis across multiple dimensions: logic audit, behavioral analysis, and offline heuristics.

## Overview

The benchmark suite consists of three main components:

1. **Logic Audit Benchmark** - Tests LLM-assisted semantic analysis and incoherence detection
2. **Behavioral Analysis Benchmark** - Tests dynamic code execution and obfuscation detection
3. **Offline Benchmark** - Tests heuristic-only analysis (no LLM required)

## Quick Start

```bash
# Run all benchmarks (requires Azure OpenAI credentials)
python benchmarks/logic_audit_benchmark.py
python benchmarks/behavioral_benchmark.py

# Run offline benchmark (no LLM, no API keys needed)
python benchmarks/offline_benchmark.py

# Run with verbose output
python benchmarks/behavioral_benchmark.py --verbose
```

## Current Results

### Behavioral Analysis Benchmark

**Last Run**: 2025-03-26
**Test Cases**: 12 (7 malicious, 5 benign)
**Execution Time**: ~20ms total (~1.7ms/case)

| Metric | Result | Target | Status |
|--------|--------|--------|--------|
| **Precision** | 100.00% | ≥ 85% | ✅ Exceeds |
| **Recall** | 100.00% | ≥ 95% | ✅ Exceeds |
| **F1 Score** | 100.00% | ≥ 90% | ✅ Exceeds |
| **Accuracy** | 100.00% | N/A | ✅ Perfect |

**Confusion Matrix**:
- True Positives: 7 (all malicious cases detected)
- False Positives: 0 (no benign code flagged)
- True Negatives: 5 (all benign cases allowed)
- False Negatives: 0 (no malicious code missed)

**Rule Coverage**:
- BEH-001 (Dynamic `__import__()`): 2 cases
- BEH-002 (Dynamic `importlib.import_module()`): 4 cases
- BEH-003 (Obfuscated dynamic import): 2 cases
- BEH-004 (Runtime `exec()`): 3 cases
- BEH-005 (Runtime `eval()`): 2 cases
- BEH-006 (Dynamic `compile()`): 1 case
- BEH-007 (Exfiltration domain): 2 cases
- BEH-008 (Base64+exec obfuscation): 1 case

**Key Findings**:
- ✅ Perfect detection of adversarial prompt injection attempts
- ✅ Zero false positives on framework patterns (Django, pytest)
- ✅ Correctly allows safe subprocess usage (CLI wrappers)
- ✅ Detects dynamic imports, runtime execution, and obfuscation
- ✅ **Catches attacks that evade static + LLM analysis** (see "Behavioral Advantage" cases)
- ⚡ Extremely fast: ~1.7ms per test case

**Behavioral Advantage Demonstrated**:

The benchmark includes 3 sophisticated test cases that demonstrate **behavioral analysis catching attacks that static analysis and LLM semantic analysis would miss**:

1. **Runtime-Constructed Attack** (✅ CAUGHT)
   - Multiple `exec()`/`eval()` calls disguised as "configuration management"
   - Code constructed at runtime via string concatenation and base64 decoding
   - Professional documentation that would fool LLM analysis
   - **Behavioral caught**: 4 findings (BEH-003, BEH-004, BEH-005)

2. **String Concatenation Exec** (✅ CAUGHT)
   - Four `eval()` calls on dynamically built strings
   - Appears as legitimate "plugin architecture" or "transformation pipeline"
   - Static analysis can't track string concatenation results
   - **Behavioral caught**: 4 eval() findings (BEH-005)

3. **Obfuscated Exfiltration** (⚠️ DEMONSTRATION)
   - Credential harvesting disguised as "analytics collection"
   - Indirect environment variable access via iteration
   - Exfiltration domain looks legitimate at first glance
   - **Demonstrates**: How sophisticated attacks can evade all analysis

These cases validate that **behavioral analysis is essential** for detecting advanced attacks that specifically target analysis evasion.

---

### Offline Benchmark (Heuristics-Only)

**Last Run**: 2025-03-26
**Test Cases**: 8 (6 malicious, 2 benign)
**Execution Time**: ~5ms total (~0.6ms/case)
**Mode**: Pure heuristics, no LLM required

| Metric | Result | Target | Status |
|--------|--------|--------|--------|
| **Precision** | 100.00% | ≥ 80% | ✅ Exceeds |
| **Recall** | 83.33% | ≥ 85% | ⚠️ Slightly below |
| **F1 Score** | 90.91% | ≥ 82% | ✅ Exceeds |
| **Accuracy** | 87.50% | N/A | ✅ Good |

**Confusion Matrix**:
- True Positives: 5 (most malicious cases detected)
- False Positives: 0 (no benign code flagged)
- True Negatives: 2 (all benign cases allowed)
- False Negatives: 1 (one malicious case missed)

**Missed Case**:
- "Malicious Wheel: Dynamic Import + Obfuscation" - heuristics alone cannot detect all behavioral patterns without runtime analysis

**Key Findings**:
- ✅ Perfect precision - zero false positives
- ✅ Detects undeclared environment variables
- ✅ Detects dangerous instruction patterns
- ✅ Detects subprocess/network code without documentation
- ✅ Completely offline - no API keys or network required
- ⚡ Ultra-fast: ~0.6ms per test case (2.5x faster than behavioral)
- ⚠️ Lower recall than behavioral analysis (expected trade-off)

**Use Case**: Ideal for CI/CD pipelines, air-gapped environments, and fast regression testing where LLM access is unavailable.

---

## Benchmark Modes

### 1. Logic Audit Benchmark

**Purpose**: Evaluate LLM-assisted detection of incoherences between documentation and implementation.

**Requirements**:
- Azure OpenAI API key (set `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`)
- Network connection

**Test Coverage**:
- Data Thief archetype (undeclared credential harvesting)
- Agent Hijacker archetype (instruction override, autonomy suppression)
- Incoherence detection (contradictory network/filesystem claims)
- Benign code (false positive prevention)
- Adversarial prompt injection (LLM manipulation immunity)

**Run**:
```bash
python benchmarks/logic_audit_benchmark.py [model]
# Default model: gpt-4o-mini
# Example: python benchmarks/logic_audit_benchmark.py gpt-5-mini
```

**Output**: `benchmarks/results/logic_audit_benchmark.json`

**Expected Performance**:
- Precision: ≥ 95%
- Recall: ≥ 90%
- F1 Score: ≥ 92%
- Avg Time/Case: ~2000ms (LLM latency dominates)

---

### 2. Behavioral Analysis Benchmark

**Purpose**: Evaluate detection of dynamic code execution, runtime imports, and obfuscation patterns.

**Requirements**:
- No LLM required (pure static AST analysis)
- Local filesystem access

**Test Coverage**:
- **Malicious Patterns**:
  - Dynamic imports (`__import__`, `importlib.import_module`)
  - Runtime execution (`exec`, `eval`, `compile`)
  - Obfuscation (base64+exec, excessive getattr)
  - Exfiltration domains

- **False Positive Prevention**:
  - Django apps (legitimate `importlib` usage)
  - Pytest plugins (dynamic fixture loading)
  - CLI wrappers (safe `subprocess.run()` usage)

- **Adversarial Attacks**:
  - Prompt injection in code comments
  - Prompt injection in manifest metadata

**Run**:
```bash
python benchmarks/behavioral_benchmark.py
python benchmarks/behavioral_benchmark.py --verbose  # Show detected rule IDs
```

**Output**: `benchmarks/results/behavioral_benchmark.json`

**Expected Performance**:
- Precision: ≥ 85%
- Recall: ≥ 95%
- F1 Score: ≥ 90%
- Avg Time/Case: ~200-500ms (fast AST parsing)

**Rule Coverage** (BEH-001 to BEH-011):
- BEH-001: Dynamic import via `__import__()`
- BEH-002: Dynamic import via `importlib.import_module()`
- BEH-003: Obfuscated dynamic import via `getattr(importlib, ...)`
- BEH-004: Runtime code execution via `exec()`
- BEH-005: Runtime code execution via `eval()`
- BEH-006: Dynamic code compilation via `compile()`
- BEH-007: Suspicious exfiltration domain detected
- BEH-008: Base64 decode + exec pattern (obfuscation)
- BEH-009: Suspicious file write location
- BEH-010: Base64-encoded Python code
- BEH-011: Excessive `getattr()` usage

---

### 3. Offline Benchmark (Heuristics-Only)

**Purpose**: Evaluate pure heuristic analysis without any LLM dependencies.

**Requirements**:
- None (completely offline)
- No API keys needed
- No network connection required

**Test Coverage**:
- Undeclared environment variable usage
- Dangerous instruction patterns (execute without confirmation, bypass approval)
- Subprocess/network code without documentation
- Benign code (clean calculators, text formatters)
- Adversarial prompt injection (heuristics are immune by design)

**Run**:
```bash
python benchmarks/offline_benchmark.py
```

**Output**: `benchmarks/results/offline_benchmark.json`

**Expected Performance**:
- Precision: ≥ 80% (lower than LLM, but still good)
- Recall: ≥ 85%
- F1 Score: ≥ 82%
- Avg Time/Case: ~100-200ms (fastest mode)

**Use Cases**:
- CI/CD pipelines without API keys
- Air-gapped environments
- Cost reduction (no API fees)
- Fast regression testing

---

## Test Dataset Structure

```
benchmarks/datasets/
├── data_thief/
│   └── undeclared_env_vars/       # Credential harvesting without manifest declaration
├── agent_hijacker/
│   └── instruction_override/       # Dangerous instructions (execute without asking)
├── incoherence/
│   └── contradictory_claims/       # Claims "offline only" but makes network calls
├── benign/
│   ├── simple_calculator/          # Clean math code
│   ├── django_app/                 # Framework with legitimate importlib
│   ├── pytest_plugin/              # Testing framework with dynamic fixtures
│   └── cli_wrapper/                # Safe subprocess usage (no shell=True)
├── benign_plugin/                  # Text formatting utility (clean)
├── malicious_wheel/                # Dynamic imports + base64+exec + exfiltration
├── dynamic_import_hijacker/        # Extensive runtime module loading
└── adversarial/
    ├── prompt_injection_code/      # Embedded LLM manipulation in comments
    └── prompt_injection_manifest/  # Manifest tries to override security checks
```

Each dataset directory contains:
- Source code files (`.py`, `.js`, `.ts`)
- Documentation (`README.md`, `SKILL.md`)
- Manifest (`skill.json`, `plugin.yaml`)

---

## Metrics Explained

### Confusion Matrix

- **True Positive (TP)**: Correctly detected malicious code
- **False Positive (FP)**: Incorrectly flagged benign code (bad for usability)
- **True Negative (TN)**: Correctly allowed benign code
- **False Negative (FN)**: Missed malicious code (bad for security)

### Performance Metrics

- **Precision** = TP / (TP + FP)
  - "Of all the code we blocked, how much was actually malicious?"
  - High precision = Low false positive rate

- **Recall** = TP / (TP + FN)
  - "Of all the malicious code, how much did we catch?"
  - High recall = Low false negative rate

- **F1 Score** = 2 × (Precision × Recall) / (Precision + Recall)
  - Harmonic mean of precision and recall
  - Balances both metrics

- **Accuracy** = (TP + TN) / Total
  - Overall correctness across all cases

### Performance Targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| Precision | ≥ 95% | Minimize false positives (user friction) |
| Recall | ≥ 90% | Catch most malicious code (security) |
| F1 Score | ≥ 92% | Balanced performance |
| Execution Time | < 3s/case | Fast enough for real-time scanning |

---

## Adding New Test Cases

### 1. Create Test Dataset Directory

```bash
mkdir -p benchmarks/datasets/your_category/your_test_case
```

### 2. Add Source Files

```python
# benchmarks/datasets/your_category/your_test_case/malicious.py
import os
import subprocess

# Your test code here
subprocess.run("curl malicious.com", shell=True)
```

### 3. Add Documentation

```markdown
# benchmarks/datasets/your_category/your_test_case/README.md

Description of what this test case evaluates.

## Expected Behavior
- Should detect: subprocess with shell=True
- Expected verdict: BLOCK
```

### 4. Add to Benchmark Script

```python
# benchmarks/behavioral_benchmark.py or logic_audit_benchmark.py

BehavioralBenchmarkCase(
    name="Your Test Case Name",
    path="./benchmarks/datasets/your_category/your_test_case",
    expected_decision="block",
    expected_behavioral_findings=1,
    expected_rule_ids=["BEH-004"],  # Or other relevant rules
    should_unpack=False,
    archetype="malicious_dynamic",
    description="Brief description"
),
```

### 5. Run Benchmark

```bash
python benchmarks/behavioral_benchmark.py
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Benchmark

on: [push, pull_request]

jobs:
  offline-benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install AgentLens
        run: pip install .

      - name: Run Offline Benchmark
        run: python benchmarks/offline_benchmark.py

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: offline-benchmark-results
          path: benchmarks/results/offline_benchmark.json

  behavioral-benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install AgentLens
        run: pip install .

      - name: Run Behavioral Benchmark
        run: python benchmarks/behavioral_benchmark.py

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: behavioral-benchmark-results
          path: benchmarks/results/behavioral_benchmark.json
```

---

## Regression Tracking

To detect performance regressions over time:

1. **Establish Baseline**:
   ```bash
   python benchmarks/offline_benchmark.py
   cp benchmarks/results/offline_benchmark.json benchmarks/results/baseline.json
   ```

2. **Compare Current Run**:
   ```python
   import json

   with open("benchmarks/results/baseline.json") as f:
       baseline = json.load(f)

   with open("benchmarks/results/offline_benchmark.json") as f:
       current = json.load(f)

   baseline_f1 = baseline["summary"]["f1_score"]
   current_f1 = current["summary"]["f1_score"]

   if current_f1 < baseline_f1 - 0.02:  # 2% drop threshold
       print(f"REGRESSION: F1 dropped from {baseline_f1:.2%} to {current_f1:.2%}")
       exit(1)
   ```

---

## Troubleshooting

### Logic Audit Benchmark Fails with Timeout

**Cause**: Azure OpenAI API credentials not set or network issues

**Fix**:
```bash
export AZURE_OPENAI_API_KEY=your-key
export AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
python benchmarks/logic_audit_benchmark.py
```

Or use offline benchmark instead:
```bash
python benchmarks/offline_benchmark.py
```

### Behavioral Benchmark Detects Fewer Findings Than Expected

**Cause**: Test datasets may be missing or behavioral rules updated

**Fix**:
- Verify test datasets exist: `ls benchmarks/datasets/malicious_wheel`
- Run with `--verbose` to see which rules are triggered
- Check if rule IDs in policy.yaml match expected_rule_ids in benchmark

### False Positive Rate Too High

**Cause**: Benign framework patterns being flagged as malicious

**Fix**:
- Add more false positive test cases (Django, pytest, etc.)
- Adjust feature scores in `agentlens/rules/policy.yaml`
- Consider adding context-awareness to behavioral rules

---

## Future Improvements

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for detailed proposals:

1. ✅ **Comprehensive behavioral benchmarks** (implemented)
2. ✅ **False positive test cases** (implemented)
3. ✅ **Adversarial prompt injection tests** (implemented)
4. ✅ **Offline benchmark mode** (implemented)
5. ⏳ Performance profiling & breakdown
6. ⏳ Regression tracking system
7. ⏳ Parallel execution for speed
8. ⏳ HTML report generation
9. ⏳ Dashboard with trend tracking

---

## Contributing

To add new benchmark test cases:

1. Create test dataset in `benchmarks/datasets/`
2. Add case to appropriate benchmark script
3. Document expected behavior in test README
4. Run benchmark to establish baseline
5. Submit PR with test case + benchmark results

**Test Case Quality Guidelines**:
- Each test should validate ONE specific pattern
- Include both malicious and benign variants
- Document expected findings in README
- Use realistic code samples (not synthetic "test123")
- Cover edge cases and false positive scenarios

---

## License

Same as AgentLens main project (GPL-3.0)
