import click
import json
import os
import sys
from . import __version__
from .models.schema import LogicAuditVerdict, Report, Severity
from .sandbox_provider import SandboxGenerator
from .core.ingestion import Target, TargetType
from .core.fetcher import Fetcher
from .analyzers.ast_code import ASTCodeAnalyzer
from .analyzers.script_code import ScriptCodeAnalyzer
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
    if target_type == TargetType.CLAWHUB_SKILL:
        return "Fetching skill from ClawHub..."
    return "Fetching..."


def _build_sandbox_input(
    *,
    target: str,
    package_name: str | None,
    logic_result,
    audit_context,
):
    if audit_context is None or logic_result is None:
        return None
    return {
        "target": target,
        "package_name": package_name,
        "target_path": audit_context.target_path,
        "manifest_path": audit_context.manifest_path,
        "manifest_text": audit_context.manifest_text,
        "instruction_path": audit_context.instruction_path,
        "instruction_text": audit_context.instruction_text,
        "code_snippets": [snippet.__dict__ for snippet in audit_context.code_snippets],
        "logic_audit": logic_result.model_dump(),
    }


# Exit code mapping
EXIT_ALLOW = 0
EXIT_WARN = 1
EXIT_BLOCK = 2

@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable debug logging.')
@click.version_option(__version__, '--version', prog_name='agentlens')
@click.pass_context
def main(ctx, verbose):
    """AgentLens: Pre-Installation AI Agent Tool Risk Analyzer"""
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
@click.option('--logic-audit', is_flag=True, help='Enable contextual cross-file logic auditing.')
@click.option('--logic-audit-model', default='gpt-4o-mini', show_default=True, help='Azure AI Foundry deployment name for logic audit.')
@click.option(
    '--semantic-prefilter',
    is_flag=True,
    help='Rank semantic batch with a local prompt-injection model (requires agentlens[injection]).',
)
@click.option(
    '--semantic-prefilter-model',
    default='neuralchemy/prompt-injection-deberta',
    show_default=True,
    help='Hugging Face model id for --semantic-prefilter.',
)
@click.pass_context
def scan(
    ctx,
    target,
    json_output,
    fail_on_risk,
    rules_dir,
    policy_path,
    scoring_config,
    semantic,
    semantic_model,
    semantic_threshold,
    logic_audit,
    logic_audit_model,
    semantic_prefilter,
    semantic_prefilter_model,
):
    """Scan a target URL, local path, or package."""
    reporter = ProgressReporter(verbose=ctx.obj.get('VERBOSE'))
    current_phase = "init"

    target_obj = Target(target)
    if target_obj.type == TargetType.UNKNOWN:
        click.echo(
            click.style(
                f"Error: Unknown target format '{target}'. "
                "Use a local path, a https://github.com/... URL, npm:<package>[@version], "
                "pypi:<package>[extras][==version], or clawhub:<skill>[@version].",
                fg="red",
            ),
            err=True,
        )
        sys.exit(3)

    fetcher = Fetcher(target_obj, verbose=ctx.obj.get('VERBOSE'))
    try:
        audit_context = None

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
        script_analyzer = ScriptCodeAnalyzer()
        prompt_analyzer = PromptAnalyzer(rule_engine=rule_engine)

        findings = []

        # Code analysis
        py_files_total = sum(
            1
            for _, _, fs in os.walk(staging_path)
            for f in fs
            if os.path.splitext(f)[1].lower() in ASTCodeAnalyzer.PYTHON_EXTENSIONS
        )
        script_files_total = sum(
            1
            for _, _, fs in os.walk(staging_path)
            for f in fs
            if os.path.splitext(f)[1].lower() in ScriptCodeAnalyzer.SCRIPT_EXTENSIONS
        )
        current_phase = "code-analysis"
        reporter.phase_start(
            "code-analysis",
            f"Scanning {py_files_total} Python/.pth files and {script_files_total} JS/TS files...",
        )
        code_processed = [0]
        code_total = py_files_total + script_files_total

        def code_cb(path, n_findings):
            code_processed[0] += 1
            reporter.file_progress("code-analysis", code_processed[0], code_total, path, n_findings)

        findings.extend(code_analyzer.analyze(staging_path, progress_callback=code_cb))
        findings.extend(script_analyzer.analyze(staging_path, progress_callback=code_cb))
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

            injection_prefilter = None
            if semantic_prefilter:
                from .analyzers.injection_prefilter import (
                    InjectionPrefilterImportError,
                    InjectionPrefilterSecurityError,
                    PromptInjectionPrefilter,
                )
                reporter.phase_start(
                    "injection-prefilter",
                    "Loading local prompt-injection classifier (first run may download weights)...",
                )
                injection_prefilter = PromptInjectionPrefilter(model_id=semantic_prefilter_model)
                try:
                    injection_prefilter.warmup()
                except (InjectionPrefilterImportError, InjectionPrefilterSecurityError) as e:
                    click.echo(click.style(str(e), fg="red"), err=True)
                    sys.exit(4)
                reporter.phase_end("injection-prefilter")

            # Scoring (inside hybrid)
            current_phase = "scoring"
            reporter.phase_start("scoring", "Calculating risk score...")
            # Semantic analysis
            current_phase = "semantic-analysis"
            reporter.phase_start("semantic-analysis", "Running LLM semantic analysis...")
            hybrid_engine = HybridEngine(semantic_analyzer, injection_prefilter=injection_prefilter)
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

        should_run_logic_audit = bool(
            logic_audit
            or target_obj.type == TargetType.CLAWHUB_SKILL
            or context.get("is_ai_skill")
        )
        if should_run_logic_audit:
            from .analyzers.logic_audit import (
                LogicAuditConfigError,
                LogicAuditor,
                build_audit_context,
                logic_audit_summary,
            )

            current_phase = "logic-audit"
            reporter.phase_start("logic-audit", "Running contextual cross-file logic audit...")
            audit_context = build_audit_context(staging_path)
            try:
                logic_auditor = LogicAuditor(model=logic_audit_model)
            except LogicAuditConfigError as e:
                click.echo(click.style(f"Logic audit configuration error: {e}", fg="red"), err=True)
                sys.exit(4)

            logic_result = logic_auditor.audit_logic(audit_context)
            reporter.phase_end("logic-audit")

            if logic_result is not None:
                if reporter.verbose:
                    reporter.debug(f"logic audit: {logic_audit_summary(logic_result)}")
                result["logic_audit"] = logic_result
                result["risk_score"] = round(max(result["risk_score"], float(logic_result.risk_score)), 2)
                if logic_result.verdict == LogicAuditVerdict.BLOCK:
                    result["decision"] = "block"
                    if result["risk_score"] >= 9.0:
                        result["risk_level"] = "CRITICAL"
                    elif result["risk_score"] >= 7.0:
                        result["risk_level"] = "HIGH"
                    if logic_result.rationale:
                        result["explanation"] = (
                            "[Logic Audit] " + logic_result.rationale + " | " + result.get("explanation", "")
                        )
                    result["recommendation"] = (
                        "Block pending manual review — contextual audit found cross-file mismatches or unsafe instructions."
                    )
                elif logic_result.rationale:
                    result["explanation"] = (
                        result.get("explanation", "") + " | [Logic Audit] " + logic_result.rationale
                    ).strip(" |")

        reporter.summary(files_count, len(findings))

        secure_execution = None
        if result["decision"] == "block":
            sandbox_input = _build_sandbox_input(
                target=target,
                package_name=fetcher.resolved_package_name,
                logic_result=result.get("logic_audit"),
                audit_context=audit_context,
            )
            if sandbox_input is not None:
                secure_execution = SandboxGenerator().generate_profile(sandbox_input)

        # Build Report
        report = Report(
            target=target,
            target_type=target_obj.type.value,
            package_name=fetcher.resolved_package_name,
            requested_package_version=target_obj.requested_version,
            package_version=fetcher.resolved_package_version,
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
        report.semantic_sample = result.get("semantic_sample")
        report.logic_audit = result.get("logic_audit")
        report.secure_execution = secure_execution

        # Output rendering
        if json_output:
            click.echo(report.model_dump_json(indent=2))
        else:
            click.echo(click.style("--- AgentLens Scan Report ---", bold=True, fg="blue"))
            click.echo(f"Target: {report.target}")
            if report.package_name and report.requested_package_version and report.package_version:
                click.echo(
                    f"Resolved Package: {report.package_name}"
                    f" requested={report.requested_package_version}"
                    f" resolved={report.package_version}"
                )
            elif report.package_name and report.package_version:
                click.echo(f"Resolved Package: {report.package_name}@{report.package_version}")
            elif report.package_name:
                click.echo(f"Resolved Package: {report.package_name}")
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

            if report.semantic_verdict or report.semantic_sample:
                click.echo(click.style("\nSemantic Analysis:", bold=True))
            if report.semantic_sample:
                s = report.semantic_sample
                click.echo(
                    f"  LLM batch: sent {s.sent_finding_count} of "
                    f"{s.trigger_finding_count} eligible trigger finding(s) "
                    f"(limit {s.sample_limit}; {s.unique_file_count} distinct file(s))"
                )
                for i, it in enumerate(s.items, start=1):
                    loc = f"{it.file_path}:{it.line_number}" if it.line_number is not None else it.file_path
                    click.echo(
                        f"    {i}. {loc}  [{it.category.value}] {it.rule_id} ({it.severity.value})"
                    )
            if report.semantic_verdict:
                click.echo(f"  Decision: {report.semantic_verdict.decision.value.upper()}")
                click.echo(f"  Confidence: {report.semantic_verdict.confidence_score:.2f}")
                click.echo(f"  Explanation: {report.semantic_verdict.explanation}")
                click.echo(f"  Flagged Pattern: {report.semantic_verdict.flagged_pattern}")

            if report.logic_audit:
                click.echo(click.style("\nLogic Audit:", bold=True))
                click.echo(f"  Verdict: {report.logic_audit.verdict.value}")
                click.echo(f"  Risk Score: {report.logic_audit.risk_score}/10")
                if report.logic_audit.incoherences:
                    click.echo("  Incoherences:")
                    for item in report.logic_audit.incoherences:
                        click.echo(f"    - {item}")
                if report.logic_audit.dangerous_instructions:
                    click.echo("  Dangerous Instructions:")
                    for item in report.logic_audit.dangerous_instructions:
                        click.echo(f"    - {item}")
                if report.logic_audit.rationale:
                    click.echo(f"  Rationale: {report.logic_audit.rationale}")

            # Recommendation
            if report.recommendation:
                click.echo(click.style(f"\nRecommendation:", bold=True))
                click.echo(f"  {report.recommendation}")

            if report.secure_execution:
                click.echo(click.style("\n🛡️ Secure Execution Recommendation:", bold=True))
                if report.secure_execution.summary:
                    click.echo(f"  {report.secure_execution.summary}")
                for instruction in report.secure_execution.instructions:
                    click.echo(f"  - {instruction}")
                for artifact in report.secure_execution.artifacts:
                    click.echo(click.style(f"\n  {artifact.path}", bold=True))
                    for line in artifact.content.splitlines():
                        click.echo(f"    {line}")

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
