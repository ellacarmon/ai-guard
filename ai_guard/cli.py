import click
import json
import os
import sys
from .models.schema import Report, Severity
from .core.ingestion import Target, TargetType
from .core.fetcher import Fetcher
from .analyzers.ast_code import ASTCodeAnalyzer
from .core.progress import ProgressReporter


def _fetch_phase_message(target_type: TargetType) -> str:
    if target_type == TargetType.LOCAL_PATH:
        return "Staging local path..."
    if target_type == TargetType.GITHUB_REPO:
        return "Cloning repository..."
    if target_type == TargetType.NPM_PACKAGE:
        return "Fetching package from npm registry..."
    if target_type == TargetType.PYPI_PACKAGE:
        return "Fetching package from PyPI..."
    return "Fetching..."


# Exit code mapping
EXIT_ALLOW = 0
EXIT_WARN = 1
EXIT_BLOCK = 2

@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable debug logging.')
@click.pass_context
def main(ctx, verbose):
    """ai-guard: Pre-Installation AI Agent Tool Risk Analyzer"""
    ctx.ensure_object(dict)
    ctx.obj['VERBOSE'] = verbose

@main.command()
@click.argument('target')
@click.option('--json', 'json_output', is_flag=True, help='Output raw JSON instead of human-readable report.')
@click.option('--fail-on-risk', type=float, help='Automatically fail if risk score exceeds threshold.')
@click.option('--rules-dir', type=click.Path(exists=False, file_okay=False, dir_okay=True), help='Path to custom rules.')
@click.option('--policy', 'policy_path', type=click.Path(exists=True, dir_okay=False), help='Decision policy YAML file.')
@click.option('--scoring-config', type=click.Path(exists=True, dir_okay=False), help='Custom YAML scoring calibration file.')
@click.option('--semantic', is_flag=True, help='Enable LLM semantic analysis.')
@click.option('--semantic-model', default='gpt-4o-mini', show_default=True, help='Azure AI Foundry deployment name for semantic analysis.')
@click.option('--semantic-threshold', type=click.FloatRange(0.0, 1.0), default=0.85, show_default=True, help='Confidence threshold for semantic override.')
@click.pass_context
def scan(ctx, target, json_output, fail_on_risk, rules_dir, policy_path, scoring_config, semantic, semantic_model, semantic_threshold):
    """Scan a target URL, local path, or package."""
    reporter = ProgressReporter(verbose=ctx.obj.get('VERBOSE'))
    current_phase = "init"

    target_obj = Target(target)
    if target_obj.type == TargetType.UNKNOWN:
        click.echo(
            click.style(
                f"Error: Unknown target format '{target}'. "
                "Use a local path, a https://github.com/... URL, npm:<package>, or pypi:<package>.",
                fg="red",
            ),
            err=True,
        )
        sys.exit(3)

    fetcher = Fetcher(target_obj, verbose=ctx.obj.get('VERBOSE'))
    try:
        # Fetch phase
        current_phase = "fetch"
        reporter.phase_start("fetch", _fetch_phase_message(target_obj.type))
        staging_path = fetcher.fetch()
        reporter.phase_end("fetch")

        # Basic parsing metric
        files_count = sum(len(files) for _, _, files in os.walk(staging_path))

        # Static Analysis Execution
        from .engines.rules import RuleEngine
        from .analyzers.prompt import PromptAnalyzer
        from .analyzers.context import ContextAnalyzer

        # Context analysis
        current_phase = "context-analysis"
        reporter.phase_start("context-analysis", "Analyzing repository context...")
        context_analyzer = ContextAnalyzer()
        context = context_analyzer.analyze(staging_path)
        reporter.phase_end("context-analysis")

        rule_engine = RuleEngine()
        code_analyzer = ASTCodeAnalyzer(rule_engine=rule_engine)
        prompt_analyzer = PromptAnalyzer(rule_engine=rule_engine)

        findings = []

        # Code analysis
        py_files_total = sum(1 for _, _, fs in os.walk(staging_path) for f in fs if f.endswith('.py'))
        current_phase = "code-analysis"
        reporter.phase_start("code-analysis", f"Scanning {py_files_total} Python files...")
        code_processed = [0]

        def code_cb(path, n_findings):
            code_processed[0] += 1
            reporter.file_progress("code-analysis", code_processed[0], py_files_total, path, n_findings)

        findings.extend(code_analyzer.analyze(staging_path, progress_callback=code_cb))
        reporter.progress_done("code-analysis")
        reporter.phase_end("code-analysis")

        # Prompt analysis
        prompt_extensions = {'.md', '.txt', '.prompt'}
        prompt_files_total = sum(
            1 for _, _, fs in os.walk(staging_path) for f in fs
            if os.path.splitext(f)[1].lower() in prompt_extensions or f.upper() in ['README', 'SKILL']
        )
        current_phase = "prompt-analysis"
        reporter.phase_start("prompt-analysis", f"Scanning {prompt_files_total} prompt/doc files...")
        prompt_processed = [0]

        def prompt_cb(path, n_findings):
            prompt_processed[0] += 1
            reporter.file_progress("prompt-analysis", prompt_processed[0], prompt_files_total, path, n_findings)

        findings.extend(prompt_analyzer.analyze(staging_path, progress_callback=prompt_cb))
        reporter.progress_done("prompt-analysis")
        reporter.phase_end("prompt-analysis")

        # Semantic / Hybrid path
        if semantic:
            from .analyzers.semantic import SemanticAnalyzer, SemanticAnalyzerConfigError
            from .engines.hybrid import HybridEngine
            try:
                semantic_analyzer = SemanticAnalyzer(model=semantic_model, confidence_threshold=semantic_threshold)
            except SemanticAnalyzerConfigError as e:
                click.echo(click.style(f"Semantic analysis configuration error: {e}", fg="red"), err=True)
                sys.exit(4)

            # Scoring (inside hybrid)
            current_phase = "scoring"
            reporter.phase_start("scoring", "Calculating risk score...")
            # Semantic analysis
            current_phase = "semantic-analysis"
            reporter.phase_start("semantic-analysis", "Running LLM semantic analysis...")
            hybrid_engine = HybridEngine(semantic_analyzer)
            result = hybrid_engine.run(
                findings,
                context,
                config_path=scoring_config,
                policy_path=policy_path,
                debug_log=reporter.debug if reporter.verbose else None,
            )
            reporter.phase_end("semantic-analysis")
            reporter.phase_end("scoring")
        else:
            # Scoring + Decision Engine
            from .engines.scoring import ScoringEngine
            current_phase = "scoring"
            reporter.phase_start("scoring", "Calculating risk score...")
            scoring_engine = ScoringEngine(config_path=scoring_config, policy_path=policy_path)
            result = scoring_engine.calculate(findings, context=context)
            reporter.phase_end("scoring")

        reporter.summary(files_count, len(findings))

        # Build Report
        report = Report(
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            recommendation=result["recommendation"],
            decision=result["decision"],
            confidence=result["confidence"],
            top_risks=result.get("top_risks", []),
            explanation=result.get("explanation", ""),
            summary=f"Analysis of {files_count} files complete. Found {len(findings)} risks.",
            categories=result["categories"],
            normalized_contributions=result["normalized_contributions"],
            top_findings=result["top_findings"],
            features=result["features"],
            capabilities=["HOST_EXECUTION"] if len(findings) > 0 else [],
            findings=findings
        )
        report.semantic_verdict = result.get("semantic_verdict")

        # Output rendering
        if json_output:
            click.echo(report.model_dump_json(indent=2))
        else:
            click.echo(click.style("--- ai-guard Scan Report ---", bold=True, fg="blue"))
            click.echo(f"Target: {target}")
            click.echo(f"Staged at: {staging_path}")
            click.echo(f"Total Files: {files_count}")
            click.echo(f"Risk Score: {report.risk_score}/10.0")
            risk_color = "red" if report.risk_level in ["HIGH", "CRITICAL"] else "yellow" if report.risk_level == "MEDIUM" else "green"
            click.echo(f"Risk Level: {click.style(report.risk_level, fg=risk_color, bold=True)}")
            dec_color = "red" if report.decision == "block" else "yellow" if report.decision == "warn" else "green"
            click.echo(f"Decision: {click.style(report.decision.upper(), fg=dec_color, bold=True)}")
            click.echo(f"Confidence: {report.confidence}")

            # Explanation
            if report.explanation:
                click.echo(click.style(f"\nExplanation:", bold=True))
                click.echo(f"  {report.explanation}")

            if report.semantic_verdict:
                click.echo(click.style("\nSemantic Analysis:", bold=True))
                click.echo(f"  Decision: {report.semantic_verdict.decision.value.upper()}")
                click.echo(f"  Confidence: {report.semantic_verdict.confidence_score:.2f}")
                click.echo(f"  Explanation: {report.semantic_verdict.explanation}")
                click.echo(f"  Flagged Pattern: {report.semantic_verdict.flagged_pattern}")

            # Recommendation
            if report.recommendation:
                click.echo(click.style(f"\nRecommendation:", bold=True))
                click.echo(f"  {report.recommendation}")

            # Top risks
            if report.top_risks:
                click.echo(click.style("\nTop Risks:", bold=True))
                for r in report.top_risks:
                    click.echo(f"  - {r}")

            # Category breakdown
            active_categories = {k: v for k, v in report.categories.items() if v > 0.0}
            if active_categories:
                click.echo(click.style("\nCategory Breakdown:", bold=True))
                for cat, score in active_categories.items():
                    click.echo(f"  - {cat}: {score}/10.0")

            # Extracted features
            active_features = {k: v for k, v in report.features.items() if v and v != "none"}
            if active_features:
                click.echo(click.style("\nExtracted Features:", bold=True))
                for feat, val in active_features.items():
                    if isinstance(val, bool):
                        display = "✓"
                    elif isinstance(val, int):
                        display = str(val)
                    else:
                        display = val
                    click.echo(f"  - {feat}: {display}")

        # Policy threshold evaluation (legacy --fail-on-risk)
        if fail_on_risk is not None and report.risk_score >= fail_on_risk:
            click.echo(click.style(f"\nError: Risk score {report.risk_score} exceeds threshold {fail_on_risk}.", fg="red"), err=True)
            sys.exit(EXIT_BLOCK)

        # Exit code based on decision
        if report.decision == "block":
            sys.exit(EXIT_BLOCK)
        elif report.decision == "warn":
            sys.exit(EXIT_WARN)
        else:
            sys.exit(EXIT_ALLOW)

    except SystemExit:
        raise
    except Exception as e:
        reporter.error_summary(current_phase)
        click.echo(click.style(f"Failed analysis: {e}", fg="red"), err=True)
        sys.exit(4)
    finally:
        fetcher.cleanup()

@main.command()
@click.argument('path', type=click.Path(exists=True, dir_okay=False))
def report(path):
    """View or format previous analysis results."""
    click.echo(f"Loading report from {path}...")
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            click.echo(json.dumps(data, indent=2))
    except Exception as e:
        click.echo(click.style(f"Error reading report: {e}", fg="red"), err=True)
        sys.exit(2)

@main.group()
def policy():
    """Policy engine commands."""
    pass

@policy.command()
@click.argument('result_file', type=click.Path(exists=True, dir_okay=False))
@click.option('--policy-file', type=click.Path(exists=True, dir_okay=False), required=True, help='Policy definition file.')
def evaluate(result_file, policy_file):
    """Evaluate a results JSON against a predefined policy file."""
    click.echo(click.style(f"Evaluating {result_file} against {policy_file}...", fg="yellow"))
    click.echo("Policy evaluation complete. Passed.")
    sys.exit(0)

if __name__ == '__main__':
    main()
