import os
import re
from typing import List, Optional

from .base import BaseAnalyzer
from ..core import ProgressCallback
from ..models.schema import Category, Finding, Severity


class ScriptCodeAnalyzer(BaseAnalyzer):
    """Lightweight JS/TS static scanner with conservative coverage reporting."""

    SCRIPT_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    CHILD_PROCESS_CALLS = ("exec", "execSync", "spawn", "spawnSync", "fork")
    DIRECT_EVAL_PATTERN = re.compile(r"\b(?:eval|Function)\s*\(")
    STRING_TIMER_PATTERN = re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*(['\"`])")
    CHILD_PROCESS_IMPORT_PATTERN = re.compile(
        r"(?:require\(\s*['\"](?:node:)?child_process['\"]\s*\)|from\s+['\"](?:node:)?child_process['\"])",
        re.MULTILINE,
    )

    def analyze(
        self,
        target_dir: str,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        script_files = [
            os.path.join(root, name)
            for root, _, files in os.walk(target_dir)
            for name in files
            if os.path.splitext(name)[1].lower() in self.SCRIPT_EXTENSIONS
        ]

        first_script_path: Optional[str] = None
        for filepath in script_files:
            relative_path = os.path.relpath(filepath, target_dir)
            if first_script_path is None:
                first_script_path = relative_path

            new_findings: List[Finding] = []
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                content = ""

            if content:
                new_findings.extend(self._scan_eval(relative_path, content))
                new_findings.extend(self._scan_string_timers(relative_path, content))
                new_findings.extend(self._scan_child_process(relative_path, content))

            findings.extend(new_findings)
            if progress_callback is not None:
                progress_callback(relative_path, len(new_findings))

        if first_script_path is not None:
            findings.append(
                Finding(
                    rule_id="JS_TS_REVIEW_REQUIRED",
                    category=Category.CODE_EXECUTION,
                    severity=Severity.HIGH,
                    file_path=first_script_path,
                    line_number=1,
                    description=(
                        "Detected JavaScript/TypeScript sources. Static coverage for this runtime "
                        "is partial, so manual review is required before treating the package as safe."
                    ),
                    confidence=0.95,
                )
            )

        return findings

    def _scan_eval(self, relative_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for match in self.DIRECT_EVAL_PATTERN.finditer(content):
            findings.append(
                Finding(
                    rule_id="JS_DYNAMIC_EVAL",
                    category=Category.CODE_EXECUTION,
                    severity=Severity.CRITICAL,
                    file_path=relative_path,
                    line_number=self._line_number(content, match.start()),
                    description="Detected dynamic JavaScript execution via eval() or Function().",
                    evidence=match.group(0),
                    confidence=0.95,
                )
            )
        return findings

    def _scan_string_timers(self, relative_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for match in self.STRING_TIMER_PATTERN.finditer(content):
            findings.append(
                Finding(
                    rule_id="JS_STRING_TIMER_EVAL",
                    category=Category.CODE_EXECUTION,
                    severity=Severity.HIGH,
                    file_path=relative_path,
                    line_number=self._line_number(content, match.start()),
                    description="Detected string-based setTimeout/setInterval execution.",
                    evidence=match.group(0),
                    confidence=0.9,
                )
            )
        return findings

    def _scan_child_process(self, relative_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        imported_child_process = bool(self.CHILD_PROCESS_IMPORT_PATTERN.search(content))

        for call_name in self.CHILD_PROCESS_CALLS:
            patterns = [
                re.compile(rf"\b(?:child_process|cp)\s*\.\s*{call_name}\s*\("),
            ]
            if imported_child_process:
                patterns.append(re.compile(rf"\b{call_name}\s*\("))

            seen_offsets = set()
            for pattern in patterns:
                for match in pattern.finditer(content):
                    if match.start() in seen_offsets:
                        continue
                    seen_offsets.add(match.start())
                    findings.append(
                        Finding(
                            rule_id="JS_CHILD_PROCESS",
                            category=Category.CODE_EXECUTION,
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            line_number=self._line_number(content, match.start()),
                            description=f"Detected child_process.{call_name}() execution.",
                            evidence=match.group(0),
                            confidence=0.9,
                        )
                    )
        return findings

    @staticmethod
    def _line_number(content: str, offset: int) -> int:
        return content.count("\n", 0, offset) + 1
