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
ai-guard scan https://github.com/pallets/flask
```

To integrate into programmatic pipelines (such as a GitHub action or a pre-flight execution check), use `--json`:

```bash
ai-guard scan https://github.com/psf/requests --json
```

For pipeline safety, `ai-guard` automatically returns semantic exit codes reflecting the decision engine state:
- `0`: ALLOW
- `1`: WARN
- `2`: BLOCK

To enforce custom strict policies, provide a custom YAML policy template:

```bash
ai-guard scan ./local_skill_folder --policy custom_policy.yml
```

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on submitting pull requests to the project.

## License
This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.
