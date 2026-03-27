# AgentLens
![License](https://img.shields.io/badge/License-GPL_v3-blue.svg)

`AgentLens` is a deterministic, pre-installation security wrapper for AI Agent skills, tools, and repositories.

It forces targeted code to run through a custom static analysis risk scoring model before allowing it to interact with your execution environment, aggressively identifying common vulnerabilities introduced by AI-generated external dependencies.

## Key Features
- **Deterministic Scanning:** Fully bounded risk scoring engine that prevents unbounded linear score accumulation.
- **Categorical Risk Silos:** Independent evaluation of `code_execution`, `prompt_injection`, `filesystem_access`, and `network_access`.
- **Policy-Driven Decision Engine:** Automatically maps combined signals into actionable `ALLOW`, `WARN`, or `BLOCK` decisions based on YAML configuration.
- **Context-Aware Scoring:** Intelligently extracts structural signals (like `is_framework`) to separate high-risk raw execution from safe library runtime internals.
- **Confidence Scoring:** Validates the strength and ambiguity of risk signals, gracefully downgrading uncertain blocks to warnings.
- **LLM Semantic Analysis:** Optional second-opinion pass powered by Azure AI Foundry that evaluates the true intent of flagged code snippets, reducing false positives without sacrificing security coverage.
- **Behavioral Analysis (NEW):** Optional deep-scan layer that detects dynamic imports, runtime code execution (`exec`/`eval`), obfuscation patterns (base64+exec), and exfiltration domains. Safely unpacks and analyzes `.whl` and `.tar.gz` archives.
- **Registry Targets:** Scan packages directly with `npm:<package>`, `pypi:<package>`, or `clawhub:<skill>` (downloads are extracted with path-traversal checks on archives).
- **JS/TS Guardrails:** JavaScript and TypeScript files are scanned for high-risk execution patterns, and `npm:` packages with JS/TS sources are never treated as clean solely because the Python AST analyzer found nothing.
- **Output Formats:** Rich CLI formatting (yielding clear human-readable explanations and recommendations), or full `Pydantic`-validated JSON for programmatic aggregation.

## Installation

### Core Scanner (Static Analysis Only)

```bash
pip install agentlens-scanner
```

This provides fast, deterministic scanning with no external dependencies. Perfect for CI/CD pipelines.

### With LLM Features (Optional)

Choose your LLM backend based on your needs:

#### Azure OpenAI (Cloud)
```bash
pip install "agentlens-scanner[azure]"
```
**Best for**: High-quality analysis, cloud environments
**Requires**: Azure OpenAI API key
**Cost**: ~$0.001 per scan

#### Local Semantic Analysis (Offline)
```bash
pip install "agentlens-scanner[local-semantic]"
```
**Best for**: Offline environments, privacy-sensitive scans, cost reduction
**Requires**: ~200MB model download (first run)
**Cost**: Free

#### All LLM Backends
```bash
pip install "agentlens-scanner[all-llm]"
```

### Legacy Options

Prompt-injection prefilter:
```bash
pip install "agentlens-scanner[injection]"
```

### Install from Source

```bash
git clone https://github.com/ellacarmon/AgentLens.git
cd AgentLens
pip install .  # Core only
pip install ".[azure]"  # With Azure OpenAI
pip install ".[local-semantic]"  # With local models
```

## Usage

### Scan targets

- **GitHub:** HTTPS URL to a repository (must be `github.com`).
- **Local path:** Directory or file on disk.
- **npm:** `npm:<package>` (e.g. `npm:lodash`) — fetches the latest tarball from the public registry.
- **PyPI:** `pypi:<package>` (e.g. `pypi:requests`) — prefers an `.tar.gz` sdist, otherwise a `.whl`.
- **ClawHub:** `clawhub:<skill>` (e.g. `clawhub:calendar-helper`) — downloads the published skill ZIP from ClawHub's public API.

Examples:

```bash
agentlens scan https://github.com/langchain-ai/langchain
agentlens scan ./local_skill_folder
agentlens scan npm:some-package
agentlens scan pypi:some-project
agentlens scan clawhub:some-skill
```

Check the installed CLI version:

```bash
agentlens --version
```

To integrate into programmatic pipelines (such as a GitHub action or a pre-flight execution check), use `--json`:

```bash
agentlens scan https://github.com/microsoft/autogen --json
```

For pipeline safety, `AgentLens` automatically returns semantic exit codes reflecting the decision engine state:
- `0`: ALLOW
- `1`: WARN
- `2`: BLOCK

To enforce custom strict policies, provide a custom YAML policy template:

```bash
agentlens scan ./local_skill_folder --policy custom_policy.yml
```

### GitHub Actions example: scan pull requests

This repository includes an example workflow at `.github/workflows/agentlens-pr-scan.yml` that scans pull requests on `opened`, `synchronize`, `reopened`, and `ready_for_review`.

It checks out the PR branch, installs `agentlens-scanner`, runs a repository scan with JSON output, and uploads the report as a workflow artifact:

```yaml
- name: Scan repository contents
  id: agentlens
  shell: bash
  run: |
    set +e
    agentlens scan . --json > agentlens-report.json
    exit_code=$?
    echo "exit_code=$exit_code" >> "$GITHUB_OUTPUT"
    exit 0
```

The example treats `BLOCK` as a failing check and leaves `WARN` visible in the workflow summary without failing the job. If you want warnings to block merges too, change the final enforcement step to fail on exit code `1` as well.

### GitHub Actions example: scan pinned AI dependencies from requirements files

This repository also includes `.github/workflows/agentlens-requirements-ai-scan.yml`, which looks for `requirements*.txt` files in a pull request, extracts pinned Python dependencies, filters them to a curated set of AI-related package names, and scans each pinned version as a `pypi:` target.

Example `requirements.txt` entries that this workflow will pick up:

```txt
openai==1.68.2
langchain==0.3.21
transformers==4.49.0
```

The example intentionally only scans exact `==` pins so the workflow analyzes the same version that would be installed from the file. Unpinned entries such as `openai>=1.0` or non-AI packages are ignored.

## LLM Semantic Analysis (Azure AI Foundry)

The static analysis engine is fast and deterministic, but can produce false positives — for example, flagging a legitimate `subprocess` call used for a local math calculation the same way it flags a reverse shell. The semantic analysis layer adds a second-opinion pass that uses an LLM to evaluate the true intent of the flagged code snippet.

When enabled, the hybrid engine runs the static tier first. If the result is `WARN` or `BLOCK` and there is at least one `code_execution` or `network_access` finding, the LLM is invoked **once per scan** on a small batch of the strongest such findings (up to three), so the model sees a bit of cross-file context instead of a single line in isolation. A high-confidence `ALLOW` verdict from the LLM overrides the static decision, updating both the final verdict and the recommendation.

To print which findings were sent to the model (paths, rules, severities), run the CLI with **verbose** on the top-level command: `agentlens -v scan ... --semantic`.

### Setup

Set the following environment variables:

```bash
export AZURE_OPENAI_API_KEY=your-key
export AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
export AZURE_OPENAI_API_VERSION=2024-12-01-preview  # optional, this is the default
```

### Usage

Add `--semantic` to any scan to enable the hybrid engine:

```bash
agentlens scan https://github.com/langchain-ai/langchain --semantic
```

Override the default deployment name or confidence threshold:

```bash
agentlens scan https://github.com/langchain-ai/langchain --semantic --semantic-model gpt-4o --semantic-threshold 0.90
```

When a semantic override is applied, the output includes a dedicated section:

```
Semantic Analysis:
  Decision: ALLOW
  Confidence: 0.95
  Explanation: The subprocess call is used for a bounded local computation with no external I/O.
  Flagged Pattern: subprocess.run with shell=True
```

If the LLM API is unavailable or returns an unparseable response, `AgentLens` degrades gracefully to the static verdict — the scan never fails due to an LLM outage.

## Behavioral Analysis

Behavioral analysis extends AgentLens beyond static AST pattern matching to detect dynamic code execution, runtime module loading, and obfuscation techniques that would otherwise evade traditional scanning.

### What It Detects

The behavioral analyzer identifies:

1. **Dynamic Imports**: Runtime module loading via `__import__()`, `importlib.import_module()`, or obfuscated `getattr(importlib, ...)` patterns
2. **Runtime Code Execution**: `exec()`, `eval()`, and `compile()` calls, with severity escalation for dynamic (variable) arguments
3. **Obfuscation Patterns**:
   - Base64-encoded Python code
   - Base64 decode combined with `exec`/`eval` (classic obfuscation)
   - Excessive `getattr()` usage indicating attribute-based obfuscation
4. **Suspicious Behavioral Patterns**:
   - Network requests to exfiltration domains (pastebin, webhooks, ngrok tunnels, etc.)
   - File writes to suspicious locations (`/tmp`, home directory)
5. **Archive Unpacking**: Safely extracts and analyzes `.whl` and `.tar.gz` packages with path-traversal protection

### When to Use It

Enable behavioral analysis when:
- Scanning PyPI wheel packages or tarballs that may contain compiled/obfuscated code
- Investigating skills that use plugin systems or dynamic loading
- Dealing with packages that have low static risk but suspicious architectural patterns
- You need deeper inspection beyond surface-level AST analysis

**Note**: Behavioral analysis adds 2-5 seconds per scan and is disabled by default for performance.

### Usage

Add `--behavioral` to any scan:

```bash
# Scan a local skill with behavioral analysis
agentlens scan ./suspicious_plugin --behavioral

# Scan a PyPI package (automatically unpacks wheel if needed)
agentlens scan pypi:analytics-helper --behavioral

# Combine with semantic analysis for maximum coverage
agentlens scan ./plugin --behavioral --semantic
```

When behavioral analysis is enabled, the output includes a dedicated summary:

```
Behavioral Analysis:
  Findings: 7
  Dynamic Imports: 3
  Runtime Execution: 2
  Obfuscation: 1
  Suspicious Patterns: 1
  Archive Unpacked: Yes
```

### Behavioral Detection Rules

The analyzer uses the following rule IDs (see `agentlens/rules/policy.yaml` for full details):

- **BEH-001**: Dynamic import via `__import__()`
- **BEH-002**: Dynamic import via `importlib.import_module()`
- **BEH-003**: Obfuscated dynamic import via `getattr(importlib, ...)`
- **BEH-004**: Runtime code execution via `exec()`
- **BEH-005**: Runtime code execution via `eval()`
- **BEH-006**: Dynamic code compilation via `compile()`
- **BEH-007**: Suspicious exfiltration domain detected
- **BEH-008**: Base64 decode + exec pattern (obfuscation)
- **BEH-009**: Suspicious file write location
- **BEH-010**: Base64-encoded Python code
- **BEH-011**: Excessive `getattr()` usage

### Risk Scoring Impact

Behavioral findings contribute to the overall risk score through the feature-driven scoring system:

- **Dynamic Imports** (variable module names): +8.5 to code_execution category
- **Runtime Execution** (`exec`/`eval` with dynamic args): +9.5 to code_execution category
- **Obfuscation** (base64+exec): +9.0 to code_execution category
- **Exfiltration Domains**: +8.0 to network_access category

These scores combine with static analysis findings through probabilistic OR aggregation to produce the final risk score.

### Safety & Performance

**Security Guarantees:**

- **No Code Execution**: The analyzer NEVER executes untrusted code. All analysis is static AST parsing only.
- **Zip/Tar Bomb Protection**:
  - Maximum extracted size: 500MB
  - Maximum single file: 100MB
  - Maximum compression ratio: 100:1
  - Maximum file count: 10,000
- **Path Traversal Prevention**: All archive members validated before extraction
- **Symlink Protection**: Symlinks are detected and skipped entirely
- **Special File Blocking**: Device files, FIFOs, and other special files are rejected
- **Filename Validation**: Null bytes, control characters, and oversized names blocked
- **Extraction Isolation**: Each member's final path is verified to stay within temp directory
- **Temporary Isolation**: Archives unpacked to isolated temp directories with automatic cleanup
- **Timeout Protection**: Per-analysis timeout of 5 seconds prevents hanging
- **Graceful Degradation**: If behavioral analysis fails, the scan continues with static analysis only

**Performance:**

- Adds 2-5 seconds per scan
- Disabled by default (opt-in with `--behavioral`)
- Efficient AST parsing with minimal overhead

## Benchmark Results

AgentLens includes a comprehensive benchmark suite validating detection accuracy and performance across multiple analysis modes.

### Current Performance

| Benchmark | Precision | Recall | F1 Score | Speed | Test Cases |
|-----------|-----------|--------|----------|-------|------------|
| **Behavioral Analysis** | 100% | 100% | 100% | ~1.5ms/case | 9 (4 malicious, 5 benign) |
| **Offline (Heuristics)** | 100% | 83% | 91% | ~0.6ms/case | 8 (6 malicious, 2 benign) |

**Key Highlights:**
- ✅ **Zero false positives** - No legitimate framework code flagged
- ✅ **Perfect behavioral detection** - Catches dynamic imports, runtime execution, obfuscation
- ✅ **Adversarial immunity** - Resists prompt injection in code and manifests
- ✅ **Ultra-fast** - Sub-millisecond analysis per package
- ✅ **Offline capable** - Heuristics mode requires no LLM or API keys

**Test Coverage:**
- Malicious patterns: Dynamic imports, `exec()`/`eval()`, base64+exec, credential exfiltration
- Benign frameworks: Django plugins, pytest fixtures, CLI wrappers
- Adversarial attacks: Prompt injection attempts in code comments and metadata

For detailed metrics, test cases, and methodology, see [benchmarks/README.md](benchmarks/README.md).

---

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on submitting pull requests to the project.

## Research

The archetype-based detection in `AgentLens` (Data Thief and Agent Hijacker) is grounded in:

> **Malicious Agent Skills in the Wild: A Large-Scale Security Empirical Study**  
> Liu et al., 2026 · [arXiv:2602.06547](https://arxiv.org/abs/2602.06547)

This paper provides the first large-scale empirical study of malicious AI agent skills, confirming 157 malicious skills across 98,380 samples. Key findings that informed our detection model:
- **84.2%** of vulnerabilities reside in natural-language skill documentation (`SKILL.md`), not executable code.
- The ecosystem splits into two negatively-correlated archetypes: **Data Thieves** (credential harvest + remote script execution, empirical **OR=556** — a statistical Odds Ratio indicating these behaviors are 556x more likely to occur together) and **Agent Hijackers** (instruction override + autonomy suppression).
- Advanced attacks use **shadow features** — capabilities present at runtime but absent from public documentation — in 100% of Level 3 (sophisticated) cases.

## License
This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.
