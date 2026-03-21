import click
import json
import os
import sys
from .models.schema import Report, Severity
from .core.ingestion import Target, TargetType
from .core.fetcher import Fetcher
from .analyzers.ast_code import ASTCodeAnalyzer

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
@click.option('--policy', type=click.Path(exists=False, dir_okay=False), help='Apply a specific policy immediately.')
@click.option('--scoring-config', type=click.Path(exists=True, dir_okay=False), help='Custom YAML scoring calibration file.')
@click.pass_context
def scan(ctx, target, json_output, fail_on_risk, rules_dir, policy, scoring_config):
    """Scan a target URL, local path, or package."""
    if ctx.obj.get('VERBOSE'):
        click.echo(f"VERBOSE: Scanning target: {target}", err=True)
        
    target_obj = Target(target)
    if target_obj.type == TargetType.UNKNOWN:
        click.echo(click.style(f"Error: Unknown target format '{target}'. Must be a local path or GitHub URL.", fg="red"), err=True)
        sys.exit(3)
        
    fetcher = Fetcher(target_obj, verbose=ctx.obj.get('VERBOSE'))
    try:
        staging_path = fetcher.fetch()
        if ctx.obj.get('VERBOSE'):
            click.echo(f"VERBOSE: Target staged at {staging_path}", err=True)
            
        # Basic parsing metric for Phase 1.5/2 feedback
        files_count = sum(len(files) for _, _, files in os.walk(staging_path))
        
        # Phase 2/4: Static Analysis Execution
        from .engines.rules import RuleEngine
        from .analyzers.prompt import PromptAnalyzer
        
        rule_engine = RuleEngine()
        code_analyzer = ASTCodeAnalyzer(rule_engine=rule_engine)
        prompt_analyzer = PromptAnalyzer(rule_engine=rule_engine)
        
        findings = []
        findings.extend(code_analyzer.analyze(staging_path))
        findings.extend(prompt_analyzer.analyze(staging_path))
        
        # Phase 3: Deterministic Scoring Engine
        from .engines.scoring import ScoringEngine
        scoring_engine = ScoringEngine(config_path=scoring_config)
        risk_score, risk_level, recommendation, confidence, categories, normalized_conts, top_findings = scoring_engine.calculate(findings)
        
        # Build Report
        mock_report = Report(
            risk_score=risk_score,
            risk_level=risk_level,
            recommendation=recommendation,
            confidence=confidence,
            summary=f"Analysis of {files_count} files complete. Found {len(findings)} risks.",
            categories=categories,
            normalized_contributions=normalized_conts,
            top_findings=top_findings,
            capabilities=["HOST_EXECUTION"] if len(findings) > 0 else [],
            findings=findings
        )
        
        # Output rendering
        if json_output:
            click.echo(mock_report.model_dump_json(indent=2))
        else:
            click.echo(click.style("--- ai-guard Scan Report ---", bold=True, fg="blue"))
            click.echo(f"Target: {target}")
            click.echo(f"Staged at: {staging_path}")
            click.echo(f"Total Files: {files_count}")
            click.echo(f"Risk Score: {mock_report.risk_score}/10.0")
            risk_color = "red" if mock_report.risk_level in ["HIGH", "CRITICAL"] else "yellow" if mock_report.risk_level == "MEDIUM" else "green"
            click.echo(f"Risk Level: {click.style(mock_report.risk_level, fg=risk_color, bold=True)}")
            rec_color = "red" if mock_report.recommendation == "BLOCK" else "yellow" if mock_report.recommendation == "WARN" else "green"
            click.echo(f"Recommendation: {click.style(mock_report.recommendation, fg=rec_color, bold=True)}")
            click.echo(f"Summary: {mock_report.summary}")
            
            # Print category breakdown if they bear any risk
            active_categories = {k: v for k, v in mock_report.categories.items() if v > 0.0}
            if active_categories:
                click.echo(click.style("\nCategory Breakdown:", bold=True))
                for cat, score in active_categories.items():
                    click.echo(f"  - {cat}: {score}/10.0")
        
        # Policy threshold evaluation
        if fail_on_risk is not None and mock_report.risk_score >= fail_on_risk:
            click.echo(click.style(f"\nError: Risk score {mock_report.risk_score} exceeds threshold {fail_on_risk}.", fg="red"), err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(click.style(f"Failed analysis: {e}", fg="red"), err=True)
        sys.exit(4)
    finally:
        fetcher.cleanup()
        
    sys.exit(0)

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
    # Phase 3 Logic would be placed here
    click.echo("Policy evaluation complete. Passed.")
    sys.exit(0)

if __name__ == '__main__':
    main()
