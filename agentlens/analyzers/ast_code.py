import ast
import math
import os
import re
from collections import Counter
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
    PYTHON_EXTENSIONS = {".py", ".pth"}
    EXECUTABLE_PTH_PREFIX = "import"
    BASE64_TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])")
    DYNAMIC_EXEC_PATTERN = re.compile(r"\b(?:exec|eval)\s*\(")
    HIGH_ENTROPY_THRESHOLD = 4.5

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
            for f in files
            if os.path.splitext(f)[1].lower() in self.PYTHON_EXTENSIONS
        ]
        for filepath in py_files:
            relative_path = os.path.relpath(filepath, target_dir)
            ext = os.path.splitext(filepath)[1].lower()
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                if ext == ".pth":
                    new_findings = self._analyze_pth_file(relative_path, content)
                else:
                    tree = ast.parse(content, filename=filepath)
                    visitor = SecurityNodeVisitor(filename=relative_path, rule_engine=self.rule_engine)
                    visitor.visit(tree)
                    new_findings = visitor.findings
                    new_findings.extend(self._scan_obfuscation(relative_path, content, tree=tree))
                findings.extend(new_findings)
            except Exception:
                # Skip files that can't be read or parsed (e.g., Python 2 syntax)
                new_findings = []

            if progress_callback is not None:
                progress_callback(relative_path, len(new_findings))
        return findings

    def _analyze_pth_file(self, relative_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            executable = line.lstrip()
            if not executable.startswith(self.EXECUTABLE_PTH_PREFIX):
                continue

            try:
                tree = ast.parse(executable, filename=relative_path)
                visitor = SecurityNodeVisitor(filename=relative_path, rule_engine=self.rule_engine)
                visitor.visit(tree)
                for finding in visitor.findings:
                    findings.append(
                        finding.model_copy(
                            update={"line_number": (finding.line_number or 1) + line_number - 1}
                        )
                    )
            except Exception:
                pass

            findings.extend(
                self._scan_obfuscation(
                    relative_path,
                    executable,
                    line_offset=line_number - 1,
                )
            )
        return findings

    def _scan_obfuscation(
        self,
        relative_path: str,
        content: str,
        *,
        tree: Optional[ast.AST] = None,
        line_offset: int = 0,
    ) -> List[Finding]:
        findings: List[Finding] = []
        seen: set[tuple[int, str]] = set()

        scan_tree = tree
        if scan_tree is None:
            try:
                scan_tree = ast.parse(content, filename=relative_path)
            except Exception:
                scan_tree = None

        if scan_tree is not None:
            for node in ast.walk(scan_tree):
                if not isinstance(node, ast.Call):
                    continue
                if not self._is_dynamic_exec(node):
                    continue
                if self._contains_base64_decode(node):
                    finding = self._obfuscation_finding(
                        relative_path,
                        (getattr(node, "lineno", 1) or 1) + line_offset,
                        "Obfuscation Detected: dynamic execution combined with base64.b64decode().",
                        self._safe_unparse(node),
                        seen=seen,
                    )
                    if finding is not None:
                        findings.append(finding)

        for match in self.BASE64_TOKEN_PATTERN.finditer(content):
            token = match.group(0)
            if self._shannon_entropy(token) < self.HIGH_ENTROPY_THRESHOLD:
                continue

            line_number = content.count("\n", 0, match.start()) + 1 + line_offset
            line_text = content.splitlines()[line_number - 1 - line_offset] if content.splitlines() else content
            if not self._is_obfuscated_execution_context(line_text):
                continue

            finding = self._obfuscation_finding(
                relative_path,
                line_number,
                "Obfuscation Detected: high-entropy Base64 payload embedded in executable code.",
                line_text.strip(),
                seen=seen,
            )
            if finding is not None:
                findings.append(finding)

        return findings

    def _obfuscation_finding(
        self,
        relative_path: str,
        line_number: int,
        description: str,
        evidence: Optional[str],
        *,
        seen: set[tuple[int, str]],
    ) -> Optional[Finding]:
        key = (line_number, description)
        if key in seen:
            return None
        seen.add(key)
        return Finding(
            rule_id="CODE_OBFUSCATION_DETECTED",
            category=Category.CODE_EXECUTION,
            severity=Severity.CRITICAL,
            file_path=relative_path,
            line_number=line_number,
            description=description,
            evidence=evidence,
            confidence=0.98,
        )

    @staticmethod
    def _safe_unparse(node: ast.AST) -> Optional[str]:
        return ast.unparse(node) if hasattr(ast, "unparse") else None

    @staticmethod
    def _is_dynamic_exec(node: ast.Call) -> bool:
        return isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval"}

    def _contains_base64_decode(self, node: ast.AST) -> bool:
        return any(self._is_base64_b64decode(child) for child in ast.walk(node))

    @staticmethod
    def _is_base64_b64decode(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "b64decode"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "base64"
        )

    def _is_obfuscated_execution_context(self, line_text: str) -> bool:
        stripped = line_text.lstrip()
        return stripped.startswith(self.EXECUTABLE_PTH_PREFIX) or bool(self.DYNAMIC_EXEC_PATTERN.search(line_text))

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        length = len(value)
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy
