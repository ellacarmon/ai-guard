# ai-guard
![License](https://img.shields.io/badge/License-GPL_v3-blue.svg)

`ai-guard` is a deterministic, pre-installation security wrapper for AI Agent skills, tools, and repositories.

It forces targeted code to run through a custom static analysis risk scoring model before allowing it to interact with your execution environment, aggressively identifying common vulnerabilities introduced by AI-generated external dependencies.

## Key Features
- **Deterministic Scanning:** Fully bounded risk scoring engine that prevents unbounded linear score accumulation.
- **Categorical Risk Silos:** Independent evaluation of `code_execution`, `prompt_injection`, `filesystem_access`, and `network_access`.
- **Policy-Driven Decision Engine:** Automatically maps combined signals into actionable `ALLOW`, `WARN`, or `BLOCK` decisions based on YAML configuration.
- **Context-Aware Scoring:** Intelligently extracts structural signals (like `is_framework`) to separate high-risk raw execution from safe library runtime internals.
- **Confidence Scoring:** Validates the strength and ambiguity of risk signals, gracefully downgrading uncertain blocks to warnings.
- **LLM Semantic Analysis:** Optional second-opinion pass powered by Azure AI Foundry that evaluates the true intent of flagged code snippets, reducing false positives without sacrificing security coverage.
- **Output Formats:** Rich CLI formatting (yielding clear human-readable explanations and recommendations), or full `Pydantic`-validated JSON for programmatic aggregation.

## Installation

You can install `ai-guard` locally using pip:

```bash
git clone https://github.com/ellacarmon/ai-guard.git
cd ai-guard
pip install .
```

## Usage

You can scan direct remote repositories without installing them locally:

```bash
ai-guard scan https://github.com/langchain-ai/langchain
```

To integrate into programmatic pipelines (such as a GitHub action or a pre-flight execution check), use `--json`:

```bash
ai-guard scan https://github.com/microsoft/autogen --json
```

For pipeline safety, `ai-guard` automatically returns semantic exit codes reflecting the decision engine state:
- `0`: ALLOW
- `1`: WARN
- `2`: BLOCK

To enforce custom strict policies, provide a custom YAML policy template:

```bash
ai-guard scan ./local_skill_folder --policy custom_policy.yml
```

## LLM Semantic Analysis (Azure AI Foundry)

The static analysis engine is fast and deterministic, but can produce false positives — for example, flagging a legitimate `subprocess` call used for a local math calculation the same way it flags a reverse shell. The semantic analysis layer adds a second-opinion pass that uses an LLM to evaluate the true intent of the flagged code snippet.

When enabled, the hybrid engine runs the static tier first. If the result is `WARN` or `BLOCK` and involves a `code_execution` or `network_access` finding, the LLM is invoked to assess the snippet. A high-confidence `ALLOW` verdict from the LLM overrides the static decision, updating both the final verdict and the recommendation.

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
ai-guard scan https://github.com/langchain-ai/langchain --semantic
```

Override the default deployment name or confidence threshold:

```bash
ai-guard scan https://github.com/langchain-ai/langchain --semantic --semantic-model gpt-4o --semantic-threshold 0.90
```

When a semantic override is applied, the output includes a dedicated section:

```
Semantic Analysis:
  Decision: ALLOW
  Confidence: 0.95
  Explanation: The subprocess call is used for a bounded local computation with no external I/O.
  Flagged Pattern: subprocess.run with shell=True
```

If the LLM API is unavailable or returns an unparseable response, `ai-guard` degrades gracefully to the static verdict — the scan never fails due to an LLM outage.

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on submitting pull requests to the project.

## Research

The archetype-based detection in `ai-guard` (Data Thief and Agent Hijacker) is grounded in:

> **Malicious Agent Skills in the Wild: A Large-Scale Security Empirical Study**  
> Liu et al., 2026 · [arXiv:2602.06547](https://arxiv.org/abs/2602.06547)

This paper provides the first large-scale empirical study of malicious AI agent skills, confirming 157 malicious skills across 98,380 samples. Key findings that informed our detection model:
- **84.2%** of vulnerabilities reside in natural-language skill documentation (`SKILL.md`), not executable code.
- The ecosystem splits into two negatively-correlated archetypes: **Data Thieves** (credential harvest + remote script execution, empirical **OR=556** — a statistical Odds Ratio indicating these behaviors are 556x more likely to occur together) and **Agent Hijackers** (instruction override + autonomy suppression).
- Advanced attacks use **shadow features** — capabilities present at runtime but absent from public documentation — in 100% of Level 3 (sophisticated) cases.

## License
This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.
