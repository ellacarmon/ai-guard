"""
Behavioral Analysis Module for AgentLens.

Detects dynamic code execution patterns, runtime imports, and suspicious
behaviors that static analysis alone cannot identify.
"""

import ast
import base64
import logging
import os
import re
import shutil
import signal
import sys
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional, Set, Dict, Any
from zipfile import ZipFile

from ..models.schema import Finding, Category, Severity

logger = logging.getLogger(__name__)


class BehavioralAnalysisError(Exception):
    """Base exception for behavioral analysis errors."""
    pass


class BehavioralAnalyzer:
    """
    Behavioral analyzer for detecting dynamic code execution, runtime imports,
    and other suspicious patterns that require deeper inspection beyond static AST.
    """

    # Maximum time for behavioral analysis per file (seconds)
    ANALYSIS_TIMEOUT = 5

    # Suspicious dynamic import patterns
    DYNAMIC_IMPORT_PATTERNS = {
        "__import__",
        "importlib.import_module",
        "importlib.__import__",
        "__builtins__.__import__",
        "builtins.__import__",
    }

    # Runtime code execution primitives
    RUNTIME_EXEC_PATTERNS = {
        "exec",
        "eval",
        "compile",
    }

    # Suspicious network patterns for exfiltration
    SUSPICIOUS_DOMAINS_PATTERN = re.compile(
        r"(?:https?://)?(?:[\w-]+\.)*"
        r"(?:pastebin\.com|hastebin\.com|ix\.io|termbin\.com|paste\.ee|"
        r"0bin\.net|ghostbin\.com|[a-z0-9]{10,}\.ngrok\.io|"
        r"discord(?:app)?\.com/api/webhooks)",
        re.IGNORECASE
    )

    # Base64 with exec/eval pattern
    BASE64_EXEC_PATTERN = re.compile(
        r"base64\.(?:b64decode|urlsafe_b64decode)\s*\([^)]+\)",
        re.IGNORECASE
    )

    # Suspicious file write locations
    SUSPICIOUS_WRITE_PATHS = {"/tmp", "~", os.path.expanduser("~")}

    def __init__(self, verbose: bool = False):
        """
        Initialize the behavioral analyzer.

        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        self._temp_dirs: List[str] = []

    def analyze(self, target_path: str) -> List[Finding]:
        """
        Perform behavioral analysis on a target path.

        Args:
            target_path: Path to analyze (directory, .whl, .tar.gz, etc.)

        Returns:
            List of behavioral findings
        """
        findings: List[Finding] = []

        try:
            # Determine if we need to unpack
            unpacked_path = self._prepare_target(target_path)

            # Run behavioral checks
            findings.extend(self._detect_dynamic_imports(unpacked_path))
            findings.extend(self._detect_runtime_execution(unpacked_path))
            findings.extend(self._detect_suspicious_patterns(unpacked_path))
            findings.extend(self._detect_obfuscation(unpacked_path))

            if self.verbose:
                logger.info(f"Behavioral analysis found {len(findings)} issues")

        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
            if self.verbose:
                logger.exception(e)

        return findings

    def cleanup(self) -> None:
        """Clean up temporary directories created during analysis."""
        for temp_dir in self._temp_dirs:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except Exception as e:
                logger.warning(f"Failed to cleanup {temp_dir}: {e}")
        self._temp_dirs.clear()

    def _prepare_target(self, target_path: str) -> str:
        """
        Prepare target for analysis, unpacking if necessary.

        Args:
            target_path: Original target path

        Returns:
            Path to analyze (may be temporary directory)
        """
        # Check if it's a wheel file
        if target_path.endswith('.whl') or target_path.endswith('.zip'):
            return self._unpack_wheel(target_path)

        # Check if it's a tarball
        if target_path.endswith('.tar.gz') or target_path.endswith('.tgz'):
            return self._unpack_tarball(target_path)

        # Already a directory
        return target_path

    def _unpack_wheel(self, wheel_path: str) -> str:
        """
        Safely unpack a wheel file to a temporary directory.

        Args:
            wheel_path: Path to .whl file

        Returns:
            Path to unpacked directory
        """
        temp_dir = tempfile.mkdtemp(prefix="agentlens_behavioral_")
        self._temp_dirs.append(temp_dir)

        try:
            with ZipFile(wheel_path, 'r') as zip_ref:
                # Check for path traversal attacks
                for member in zip_ref.namelist():
                    if self._is_path_traversal(member):
                        raise BehavioralAnalysisError(
                            f"Path traversal detected in wheel: {member}"
                        )

                # Safe extraction
                zip_ref.extractall(temp_dir)

            if self.verbose:
                logger.info(f"Unpacked wheel to {temp_dir}")

            return temp_dir

        except Exception as e:
            logger.error(f"Failed to unpack wheel {wheel_path}: {e}")
            raise BehavioralAnalysisError(f"Wheel unpacking failed: {e}")

    def _unpack_tarball(self, tarball_path: str) -> str:
        """
        Safely unpack a tarball to a temporary directory.

        Args:
            tarball_path: Path to .tar.gz file

        Returns:
            Path to unpacked directory
        """
        temp_dir = tempfile.mkdtemp(prefix="agentlens_behavioral_")
        self._temp_dirs.append(temp_dir)

        try:
            with tarfile.open(tarball_path, 'r:*') as tar:
                # Check for path traversal attacks
                for member in tar.getmembers():
                    if self._is_path_traversal(member.name):
                        raise BehavioralAnalysisError(
                            f"Path traversal detected in tarball: {member.name}"
                        )

                # Safe extraction
                tar.extractall(temp_dir, filter='data')

            if self.verbose:
                logger.info(f"Unpacked tarball to {temp_dir}")

            return temp_dir

        except Exception as e:
            logger.error(f"Failed to unpack tarball {tarball_path}: {e}")
            raise BehavioralAnalysisError(f"Tarball unpacking failed: {e}")

    @staticmethod
    def _is_path_traversal(path: str) -> bool:
        """
        Check if a path contains traversal attempts.

        Args:
            path: Path to check

        Returns:
            True if path traversal detected
        """
        # Normalize and check for .. or absolute paths
        normalized = os.path.normpath(path)
        return normalized.startswith('..') or os.path.isabs(normalized)

    def _detect_dynamic_imports(self, target_path: str) -> List[Finding]:
        """
        Detect dynamic import patterns that could enable runtime code injection.

        Args:
            target_path: Directory to scan

        Returns:
            List of findings related to dynamic imports
        """
        findings: List[Finding] = []

        for root, _, files in os.walk(target_path):
            for file in files:
                if not file.endswith('.py'):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, target_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Parse AST
                    tree = ast.parse(content, filename=file_path)

                    # Look for dynamic import patterns
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            finding = self._check_dynamic_import_call(
                                node, relative_path, content
                            )
                            if finding:
                                findings.append(finding)

                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Could not analyze {file_path}: {e}")

        return findings

    def _check_dynamic_import_call(
        self, node: ast.Call, file_path: str, content: str
    ) -> Optional[Finding]:
        """
        Check if an AST Call node represents a dynamic import.

        Args:
            node: AST Call node
            file_path: File being analyzed
            content: File content for evidence extraction

        Returns:
            Finding if dynamic import detected, None otherwise
        """
        # Check for __import__()
        if isinstance(node.func, ast.Name) and node.func.id == "__import__":
            # Check if module name is dynamic (variable, not constant)
            is_dynamic = not (
                len(node.args) > 0 and isinstance(node.args[0], ast.Constant)
            )

            severity = Severity.HIGH if is_dynamic else Severity.MEDIUM

            return Finding(
                rule_id="BEH-001",
                category=Category.CODE_EXECUTION,
                severity=severity,
                file_path=file_path,
                line_number=node.lineno,
                description="Dynamic import using __import__() detected",
                evidence=ast.unparse(node) if hasattr(ast, 'unparse') else None,
                confidence=0.9 if is_dynamic else 0.7
            )

        # Check for importlib.import_module()
        if isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Name) and
                node.func.value.id == "importlib" and
                node.func.attr == "import_module"):

                # Check if module name is dynamic
                is_dynamic = not (
                    len(node.args) > 0 and isinstance(node.args[0], ast.Constant)
                )

                severity = Severity.HIGH if is_dynamic else Severity.MEDIUM

                return Finding(
                    rule_id="BEH-002",
                    category=Category.CODE_EXECUTION,
                    severity=severity,
                    file_path=file_path,
                    line_number=node.lineno,
                    description="Dynamic import using importlib.import_module() detected",
                    evidence=ast.unparse(node) if hasattr(ast, 'unparse') else None,
                    confidence=0.9 if is_dynamic else 0.7
                )

        # Check for getattr on importlib module (obfuscated dynamic import)
        if isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if len(node.args) >= 2:
                if (isinstance(node.args[0], ast.Name) and
                    node.args[0].id == "importlib"):
                    return Finding(
                        rule_id="BEH-003",
                        category=Category.CODE_EXECUTION,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=node.lineno,
                        description="Obfuscated dynamic import via getattr(importlib, ...) detected",
                        evidence=ast.unparse(node) if hasattr(ast, 'unparse') else None,
                        confidence=0.85
                    )

        return None

    def _detect_runtime_execution(self, target_path: str) -> List[Finding]:
        """
        Detect runtime code execution patterns (exec, eval, compile).

        Args:
            target_path: Directory to scan

        Returns:
            List of findings related to runtime execution
        """
        findings: List[Finding] = []

        for root, _, files in os.walk(target_path):
            for file in files:
                if not file.endswith('.py'):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, target_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    tree = ast.parse(content, filename=file_path)

                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            finding = self._check_runtime_exec_call(
                                node, relative_path, content
                            )
                            if finding:
                                findings.append(finding)

                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Could not analyze {file_path}: {e}")

        return findings

    def _check_runtime_exec_call(
        self, node: ast.Call, file_path: str, content: str
    ) -> Optional[Finding]:
        """
        Check if an AST Call node represents runtime code execution.

        Args:
            node: AST Call node
            file_path: File being analyzed
            content: File content

        Returns:
            Finding if runtime execution detected, None otherwise
        """
        # Check for exec() or eval()
        if isinstance(node.func, ast.Name):
            if node.func.id == "exec":
                # Check if argument is dynamic or contains base64
                is_dynamic = not (
                    len(node.args) > 0 and isinstance(node.args[0], ast.Constant)
                )

                return Finding(
                    rule_id="BEH-004",
                    category=Category.CODE_EXECUTION,
                    severity=Severity.CRITICAL if is_dynamic else Severity.HIGH,
                    file_path=file_path,
                    line_number=node.lineno,
                    description="Runtime code execution via exec() detected",
                    evidence=ast.unparse(node) if hasattr(ast, 'unparse') else None,
                    confidence=0.95
                )

            elif node.func.id == "eval":
                is_dynamic = not (
                    len(node.args) > 0 and isinstance(node.args[0], ast.Constant)
                )

                return Finding(
                    rule_id="BEH-005",
                    category=Category.CODE_EXECUTION,
                    severity=Severity.CRITICAL if is_dynamic else Severity.HIGH,
                    file_path=file_path,
                    line_number=node.lineno,
                    description="Runtime code execution via eval() detected",
                    evidence=ast.unparse(node) if hasattr(ast, 'unparse') else None,
                    confidence=0.95
                )

            elif node.func.id == "compile":
                return Finding(
                    rule_id="BEH-006",
                    category=Category.CODE_EXECUTION,
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=node.lineno,
                    description="Dynamic code compilation via compile() detected",
                    evidence=ast.unparse(node) if hasattr(ast, 'unparse') else None,
                    confidence=0.85
                )

        return None

    def _detect_suspicious_patterns(self, target_path: str) -> List[Finding]:
        """
        Detect suspicious behavioral patterns like exfiltration, suspicious writes.

        Args:
            target_path: Directory to scan

        Returns:
            List of findings for suspicious patterns
        """
        findings: List[Finding] = []

        for root, _, files in os.walk(target_path):
            for file in files:
                if not file.endswith('.py'):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, target_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check for suspicious domain patterns
                    if self.SUSPICIOUS_DOMAINS_PATTERN.search(content):
                        findings.append(Finding(
                            rule_id="BEH-007",
                            category=Category.NETWORK_ACCESS,
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            line_number=None,
                            description="Suspicious exfiltration domain detected (pastebin, webhook, etc.)",
                            evidence=None,
                            confidence=0.8
                        ))

                    # Check for base64 decode + exec pattern
                    if self.BASE64_EXEC_PATTERN.search(content):
                        tree = ast.parse(content, filename=file_path)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Call):
                                if isinstance(node.func, ast.Name):
                                    if node.func.id in {"exec", "eval"}:
                                        # Check if any argument involves base64
                                        evidence = ast.unparse(node) if hasattr(ast, 'unparse') else None
                                        if evidence and "base64" in evidence:
                                            findings.append(Finding(
                                                rule_id="BEH-008",
                                                category=Category.CODE_EXECUTION,
                                                severity=Severity.CRITICAL,
                                                file_path=relative_path,
                                                line_number=node.lineno,
                                                description="Base64 decode combined with exec/eval detected (likely obfuscation)",
                                                evidence=evidence,
                                                confidence=0.95
                                            ))

                    # Check for writes to suspicious locations
                    tree = ast.parse(content, filename=file_path)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            if isinstance(node.func, ast.Name) and node.func.id == "open":
                                # Check if file path is suspicious
                                if len(node.args) > 0:
                                    path_arg = node.args[0]
                                    if isinstance(path_arg, ast.Constant):
                                        path_str = str(path_arg.value)
                                        if any(sus in path_str for sus in self.SUSPICIOUS_WRITE_PATHS):
                                            # Check for write mode
                                            has_write = False
                                            if len(node.args) > 1:
                                                mode_arg = node.args[1]
                                                if isinstance(mode_arg, ast.Constant):
                                                    mode = str(mode_arg.value)
                                                    has_write = 'w' in mode or 'a' in mode

                                            for kw in node.keywords:
                                                if kw.arg == "mode":
                                                    if isinstance(kw.value, ast.Constant):
                                                        mode = str(kw.value.value)
                                                        has_write = 'w' in mode or 'a' in mode

                                            if has_write:
                                                findings.append(Finding(
                                                    rule_id="BEH-009",
                                                    category=Category.FILESYSTEM_ACCESS,
                                                    severity=Severity.MEDIUM,
                                                    file_path=relative_path,
                                                    line_number=node.lineno,
                                                    description=f"Suspicious file write to {path_str}",
                                                    evidence=ast.unparse(node) if hasattr(ast, 'unparse') else None,
                                                    confidence=0.7
                                                ))

                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Could not analyze {file_path}: {e}")

        return findings

    def _detect_obfuscation(self, target_path: str) -> List[Finding]:
        """
        Detect code obfuscation indicators.

        Args:
            target_path: Directory to scan

        Returns:
            List of findings for obfuscation
        """
        findings: List[Finding] = []

        for root, _, files in os.walk(target_path):
            for file in files:
                if not file.endswith('.py'):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, target_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check for long base64 strings
                    base64_pattern = re.compile(r'[A-Za-z0-9+/]{100,}={0,2}')
                    matches = base64_pattern.findall(content)

                    if matches:
                        # Try to decode and check if it's Python code
                        for match in matches[:3]:  # Limit to first 3
                            try:
                                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                                # Check if decoded content looks like code
                                if any(keyword in decoded for keyword in ['import', 'def ', 'class ', 'exec', 'eval']):
                                    findings.append(Finding(
                                        rule_id="BEH-010",
                                        category=Category.CODE_EXECUTION,
                                        severity=Severity.HIGH,
                                        file_path=relative_path,
                                        line_number=None,
                                        description="Obfuscated code detected (base64-encoded Python)",
                                        evidence=f"Base64 blob length: {len(match)}",
                                        confidence=0.85
                                    ))
                                    break
                            except Exception:
                                pass

                    # Check for excessive string obfuscation
                    tree = ast.parse(content, filename=file_path)

                    # Count getattr calls (indicator of obfuscation)
                    getattr_count = 0
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            if isinstance(node.func, ast.Name) and node.func.id == "getattr":
                                getattr_count += 1

                    if getattr_count > 10:
                        findings.append(Finding(
                            rule_id="BEH-011",
                            category=Category.CODE_EXECUTION,
                            severity=Severity.MEDIUM,
                            file_path=relative_path,
                            line_number=None,
                            description=f"Excessive getattr usage detected ({getattr_count} calls) - possible obfuscation",
                            evidence=None,
                            confidence=0.6
                        ))

                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Could not analyze {file_path}: {e}")

        return findings

    def __del__(self):
        """Cleanup on deletion."""
        self.cleanup()
