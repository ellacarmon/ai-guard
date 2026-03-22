import ast
import os
from typing import List, Optional
from .base import BaseAnalyzer
from ..models.schema import Finding, Category, Severity
from ..engines.rules import RuleEngine
from ..core import ProgressCallback

class SecurityNodeVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, rule_engine: RuleEngine):
        self.filename = filename
        self.findings: List[Finding] = []
        self.rule_engine = rule_engine
        
        # Pre-filter rules for speed during traversal
        self.call_name_rules = self.rule_engine.get_rules_by_type("ast_call_name")
        self.call_attr_rules = self.rule_engine.get_rules_by_type("ast_call_attr")
        self.subprocess_shell_rules = self.rule_engine.get_rules_by_type("ast_subprocess_shell")
        self.subprocess_noshell_rules = self.rule_engine.get_rules_by_type("ast_subprocess_noshell")
        
    def visit_Call(self, node: ast.Call):
        # Functions natively imported: exec(), eval()
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            for rule in self.call_name_rules:
                if func_name in rule.target:
                    self.findings.append(Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        category=rule.category,
                        file_path=self.filename,
                        line_number=node.lineno,
                        description=f"{rule.description} Target: '{func_name}()'",
                        evidence=ast.unparse(node) if hasattr(ast, 'unparse') else None,
                        confidence=getattr(rule, 'confidence_base', 1.0)
                    ))
        # Methods on imported modules e.g subprocess.Popen()
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                
                # Check abstract call attr rules (e.g. os.system, os.popen)
                for rule in self.call_attr_rules:
                    if module_name == rule.module and attr_name in rule.target:
                        self.findings.append(Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            category=rule.category,
                            file_path=self.filename,
                            line_number=node.lineno,
                            description=f"{rule.description} Target: '{module_name}.{attr_name}()'",
                            evidence=ast.unparse(node) if hasattr(ast, 'unparse') else None,
                            confidence=getattr(rule, 'confidence_base', 0.8)  # Slightly lower confidence for abstract module matches
                        ))

                if module_name == 'subprocess' and attr_name in ['Popen', 'run', 'call', 'check_call', 'check_output']:
                    # Look for shell=True
                    is_shell = False
                    for kw in node.keywords:
                        if kw.arg == 'shell':
                            if isinstance(kw.value, ast.Constant) and getattr(kw.value, 'value', False) is True:
                                is_shell = True
                            elif hasattr(ast, 'NameConstant') and isinstance(kw.value, getattr(ast, 'NameConstant')) and kw.value.value is True:
                                is_shell = True
                    
                    rules_to_check = self.subprocess_shell_rules if is_shell else self.subprocess_noshell_rules
                    for rule in rules_to_check:
                        self.findings.append(Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            category=rule.category,
                            file_path=self.filename,
                            line_number=node.lineno,
                            description=f"{rule.description} Target: 'subprocess.{attr_name}()' (shell={is_shell})",
                            evidence=ast.unparse(node) if hasattr(ast, 'unparse') else None,
                            confidence=1.0 if is_shell else getattr(rule, 'confidence_base', 0.9)
                        ))
        
        # Traverse children natively
        self.generic_visit(node)

class ASTCodeAnalyzer(BaseAnalyzer):
    def __init__(self, rule_engine: RuleEngine):
        self.rule_engine = rule_engine

    def analyze(
        self,
        target_dir: str,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> List[Finding]:
        findings = []
        py_files = [
            os.path.join(root, f)
            for root, _, files in os.walk(target_dir)
            for f in files if f.endswith('.py')
        ]
        for filepath in py_files:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                tree = ast.parse(content, filename=filepath)
                relative_path = os.path.relpath(filepath, target_dir)

                visitor = SecurityNodeVisitor(filename=relative_path, rule_engine=self.rule_engine)
                visitor.visit(tree)
                new_findings = visitor.findings
                findings.extend(new_findings)
            except Exception:
                # Skip files that can't be read or parsed (e.g., Python 2 syntax)
                new_findings = []
                relative_path = os.path.relpath(filepath, target_dir)

            if progress_callback is not None:
                progress_callback(relative_path, len(new_findings))
        return findings
