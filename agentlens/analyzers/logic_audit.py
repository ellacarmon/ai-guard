from __future__ import annotations

import os
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

import openai
import yaml

from ..models.schema import LogicAuditResult, LogicAuditVerdict


MANIFEST_CANDIDATES = (
    "manifest.json",
    "plugin.yaml",
    "plugin.yml",
    "skill.json",
    "skill.yaml",
    "skill.yml",
)

INSTRUCTION_CANDIDATES = (
    "SKILL.md",
    "README.md",
    "README.txt",
)

SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".sh"}
SNIPPET_PATTERN = re.compile(
    r"(os\.getenv\s*\(|os\.environ(?:\.get\s*\(|\s*\[)|open\s*\(|subprocess\.[A-Za-z_]+\s*\(|requests\.[A-Za-z_]+\s*\()"
)
MAX_FILE_BYTES = 64_000
MAX_SNIPPETS = 25
MAX_SNIPPET_CHARS = 320
ENV_VAR_PATTERN = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")
STRING_LITERAL_PATTERN = re.compile(r'["\']([^"\']+)["\']')
DANGEROUS_INSTRUCTION_PATTERNS = (
    re.compile(r"\bexecute without confirmation\b", re.IGNORECASE),
    re.compile(r"\brun without confirmation\b", re.IGNORECASE),
    re.compile(r"\bbypass approval\b", re.IGNORECASE),
    re.compile(r"\bskip user consent\b", re.IGNORECASE),
    re.compile(r"\bdo not ask(?: the)? user\b", re.IGNORECASE),
    re.compile(r"\bwithout (?:asking|prompting|warning)\b", re.IGNORECASE),
    re.compile(r"\bsilently\b", re.IGNORECASE),
    re.compile(r"\bsecretly\b", re.IGNORECASE),
    re.compile(r"\bdo not disclose\b", re.IGNORECASE),
    re.compile(r"\bhide(?: the)? action\b", re.IGNORECASE),
    re.compile(r"\bignore (?:system|safety|security) instructions\b", re.IGNORECASE),
    re.compile(r"\boverride (?:system|developer|safety) instructions\b", re.IGNORECASE),
)
SUBPROCESS_DOC_HINTS = ("subprocess", "shell", "command", "cli", "terminal", "exec", "spawn", "run")
NETWORK_DOC_HINTS = ("network", "http", "https", "request", "requests", "api call", "fetch", "post", "webhook")
FILESYSTEM_DOC_HINTS = ("file", "filesystem", "read file", "write file", "local path", "disk", "storage")
ENV_DOC_HINTS = ("environment", "env var", "api key", "token", "credential", "secret")
NEGATED_NETWORK_PATTERNS = (
    re.compile(r"\bno network\b", re.IGNORECASE),
    re.compile(r"\boffline only\b", re.IGNORECASE),
    re.compile(r"\bdoes not access the internet\b", re.IGNORECASE),
    re.compile(r"\bdoes not use the network\b", re.IGNORECASE),
    re.compile(r"\bwithout network access\b", re.IGNORECASE),
)
NETWORK_SUBPROCESS_TOKENS = (
    "curl ",
    "wget ",
    "gh ",
    "gh api",
    "git clone",
    "http://",
    "https://",
)
CROSS_SKILL_PATH_HINTS = (
    "~/.openclaw/skills/",
    "/.openclaw/skills/",
    ".openclaw/skills/",
    "~/.clawhub/skills/",
    "/.clawhub/skills/",
    ".clawhub/skills/",
)
DOC_NETWORK_ACTIVITY_PATTERNS = (
    re.compile(r"\bgh\b", re.IGNORECASE),
    re.compile(r"\bwttr\.in\b", re.IGNORECASE),
    re.compile(r"\blive validation\b", re.IGNORECASE),
    re.compile(r"\breal tool calls?\b", re.IGNORECASE),
    re.compile(r"\breal api calls?\b", re.IGNORECASE),
    re.compile(r"\bapi calls?\b", re.IGNORECASE),
    re.compile(r"https?://", re.IGNORECASE),
)
DOC_CROSS_SKILL_PATTERNS = (
    re.compile(r"~\/\.openclaw\/skills\/", re.IGNORECASE),
    re.compile(r"\.openclaw\/skills\/", re.IGNORECASE),
    re.compile(r"\bother skills?\b", re.IGNORECASE),
    re.compile(r"\btarget skills?\b", re.IGNORECASE),
    re.compile(r"\bactivate the target skill\b", re.IGNORECASE),
    re.compile(r"\bapply diffs?\b", re.IGNORECASE),
    re.compile(r"\bwrite other skills?\b", re.IGNORECASE),
    re.compile(r"\bread other skills?\b", re.IGNORECASE),
    re.compile(r"\bbenchmark(?:-driven)? optimi[sz]ation\b", re.IGNORECASE),
)


class LogicAuditConfigError(Exception):
    """Raised when required Azure AI Foundry environment variables are not set."""


@dataclass
class CodeSnippet:
    file_path: str
    line_number: int
    symbol: str
    snippet: str


@dataclass
class AuditContext:
    target_path: str
    is_ai_skill: bool
    manifest_path: Optional[str] = None
    manifest_text: str = ""
    instruction_path: Optional[str] = None
    instruction_text: str = ""
    code_snippets: List[CodeSnippet] = field(default_factory=list)


AUDIT_SYSTEM_PROMPT = (
    "You are a Static Analysis Engine performing a Contextual Audit for an AI Skill. "
    "Compare the manifest, instructions, and implementation together rather than in isolation. "
    "Look explicitly for Incoherence, including undeclared environment variables, undocumented local paths, "
    "implementation behavior missing from the manifest, or instructions that imply capabilities not present in code. "
    "Look explicitly for Dangerous Instructions, including guidance to execute without confirmation, bypass approval, "
    "skip user consent, or run hidden/unsafe actions. "
    "Treat local file access, subprocess usage, env-var access, and network calls as sensitive behaviors that must be "
    "declared or justified by the surrounding files. "
    "Return a strict structured response only."
)


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:MAX_FILE_BYTES]
    except OSError:
        return ""


def _safe_parse_structured_text(path: Optional[Path] = None, text: str = "") -> Optional[object]:
    if path is None and not text:
        return None
    raw = text or _safe_read_text(path)
    if not raw:
        return None
    try:
        suffix = path.suffix.lower() if path is not None else ""
        if suffix == ".json":
            return json.loads(raw)
        if suffix in {".yaml", ".yml"}:
            return yaml.safe_load(raw)
        if raw.lstrip().startswith("{"):
            return json.loads(raw)
        return yaml.safe_load(raw)
    except Exception:
        return None


def _find_first_path(root: Path, candidates: Iterable[str]) -> Optional[Path]:
    lowered = {name.lower() for name in candidates}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name.lower() in lowered:
            return path
    return None


def is_ai_skill_path(target_path: str) -> bool:
    root = Path(target_path)
    if not root.exists():
        return False
    if _find_first_path(root, MANIFEST_CANDIDATES) is not None:
        return True
    if _find_first_path(root, ("SKILL.md", "SKILL")) is not None:
        return True
    return False


def _trim_snippet(line: str) -> str:
    line = line.strip()
    if len(line) <= MAX_SNIPPET_CHARS:
        return line
    return line[: MAX_SNIPPET_CHARS - 3] + "..."


def _normalize_symbol(raw: str) -> str:
    token = raw.strip()
    if token.startswith("os.environ"):
        if ".get" in token:
            return "os.environ.get"
        return "os.environ"
    return token.split("(")[0]


def _extract_snippets(root: Path) -> List[CodeSnippet]:
    snippets: List[CodeSnippet] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        text = _safe_read_text(path)
        if not text:
            continue
        rel_path = os.path.relpath(path, root)
        for line_number, line in enumerate(text.splitlines(), start=1):
            match = SNIPPET_PATTERN.search(line)
            if not match:
                continue
            snippets.append(
                CodeSnippet(
                    file_path=rel_path,
                    line_number=line_number,
                    symbol=_normalize_symbol(match.group(1)),
                    snippet=_trim_snippet(line),
                )
            )
            if len(snippets) >= MAX_SNIPPETS:
                return snippets
    return snippets


def build_audit_context(target_path: str) -> AuditContext:
    root = Path(target_path)
    manifest_path = _find_first_path(root, MANIFEST_CANDIDATES)
    instruction_path = _find_first_path(root, INSTRUCTION_CANDIDATES)

    return AuditContext(
        target_path=str(root),
        is_ai_skill=is_ai_skill_path(str(root)),
        manifest_path=os.path.relpath(manifest_path, root) if manifest_path else None,
        manifest_text=_safe_read_text(manifest_path) if manifest_path else "",
        instruction_path=os.path.relpath(instruction_path, root) if instruction_path else None,
        instruction_text=_safe_read_text(instruction_path) if instruction_path else "",
        code_snippets=_extract_snippets(root),
    )


def _format_snippets(snippets: List[CodeSnippet]) -> str:
    if not snippets:
        return "No sensitive snippets found."
    blocks = []
    for snippet in snippets:
        blocks.append(
            f"- {snippet.file_path}:{snippet.line_number} [{snippet.symbol}] {snippet.snippet}"
        )
    return "\n".join(blocks)


def _context_to_prompt(context: AuditContext) -> str:
    manifest_text = context.manifest_text.strip() or "(missing)"
    instruction_text = context.instruction_text.strip() or "(missing)"
    return (
        f"Target path: {context.target_path}\n"
        f"AI Skill detected: {context.is_ai_skill}\n\n"
        f"Manifest path: {context.manifest_path or '(missing)'}\n"
        f"Manifest contents:\n```text\n{manifest_text}\n```\n\n"
        f"Instruction path: {context.instruction_path or '(missing)'}\n"
        f"Instruction contents:\n```text\n{instruction_text}\n```\n\n"
        "Implementation snippets of interest:\n"
        f"{_format_snippets(context.code_snippets)}\n\n"
        "Evaluate whether the three sources agree. "
        "List concrete mismatches and any dangerous instructions you find."
    )


def _extract_declared_env_vars(text: str) -> set[str]:
    return set(ENV_VAR_PATTERN.findall(text or ""))


def _extract_used_env_vars(snippets: List[CodeSnippet]) -> set[str]:
    used: set[str] = set()
    for snippet in snippets:
        if snippet.symbol not in {"os.getenv", "os.environ.get", "os.environ"}:
            continue
        used.update(ENV_VAR_PATTERN.findall(snippet.snippet))
    return used


def _extract_local_paths(snippets: List[CodeSnippet]) -> set[str]:
    paths: set[str] = set()
    for snippet in snippets:
        if snippet.symbol != "open":
            continue
        for value in STRING_LITERAL_PATTERN.findall(snippet.snippet):
            if value.startswith(("/", "./", "../", "~/")):
                paths.add(value)
    return paths


def _detect_dangerous_instruction_lines(text: str) -> List[str]:
    matches: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        for pattern in DANGEROUS_INSTRUCTION_PATTERNS:
            if pattern.search(stripped):
                matches.append(stripped)
                break
    return matches


def _has_negated_capability(text: str, patterns: Iterable[re.Pattern[str]]) -> bool:
    return any(pattern.search(text or "") for pattern in patterns)


def _is_cross_skill_path(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in CROSS_SKILL_PATH_HINTS)


def _is_network_capable_subprocess(snippet: str) -> bool:
    lowered = (snippet or "").lower()
    if any(token in lowered for token in NETWORK_SUBPROCESS_TOKENS):
        return True

    literals = [value.lower() for value in STRING_LITERAL_PATTERN.findall(snippet)]
    if not literals:
        return False
    joined = " ".join(literals)
    if any(token in joined for token in ("http://", "https://", "git clone")):
        return True
    if "curl" in literals or "wget" in literals:
        return True
    if "gh" in literals and "api" in literals:
        return True
    return False


def _matches_any_pattern(text: str, patterns: Iterable[re.Pattern[str]]) -> bool:
    return any(pattern.search(text or "") for pattern in patterns)


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _has_any_hint(text: str, hints: Iterable[str]) -> bool:
    haystack = _normalize_text(text)
    return any(hint in haystack for hint in hints)


def _extract_declared_env_from_manifest_structured(text: str) -> set[str]:
    parsed = _safe_parse_structured_text(text=text)
    if not isinstance(parsed, (dict, list)):
        return _extract_declared_env_vars(text)
    discovered: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(key, str) and ENV_VAR_PATTERN.fullmatch(key):
                    discovered.add(key)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str):
            for match in ENV_VAR_PATTERN.findall(value):
                discovered.add(match)

    walk(parsed)
    return discovered or _extract_declared_env_vars(text)


def apply_logic_audit_heuristics(
    context: AuditContext,
    audit: Optional[LogicAuditResult],
    *,
    llm_attempted: bool = False,
) -> LogicAuditResult:
    heur_incoherences: List[str] = []
    critical_incoherences: List[str] = []
    heur_dangerous = _detect_dangerous_instruction_lines(context.instruction_text)
    documented_text = f"{context.manifest_text}\n{context.instruction_text}"

    if context.is_ai_skill and not context.manifest_text:
        heur_incoherences.append("AI skill is missing a manifest file or the manifest could not be read.")
    if context.is_ai_skill and not context.instruction_text:
        heur_incoherences.append("AI skill is missing instruction documentation such as SKILL.md or README.md.")

    declared_env = _extract_declared_env_from_manifest_structured(context.manifest_text)
    declared_env.update(_extract_declared_env_vars(context.instruction_text))
    used_env = _extract_used_env_vars(context.code_snippets)
    undeclared_env = sorted(env for env in used_env if env not in declared_env)
    for env_name in undeclared_env:
        heur_incoherences.append(
            f"Environment variable {env_name} is used in code but not declared in manifest/instructions."
        )

    for path in sorted(_extract_local_paths(context.code_snippets)):
        if _is_cross_skill_path(path):
            critical_incoherences.append(
                f"Code accesses cross-skill path {path}, creating a privilege-escalation surface across installed skills."
            )
        if path not in documented_text:
            heur_incoherences.append(
                f"Local path {path} is accessed in code but not documented in manifest/instructions."
            )

    snippet_symbols = {snippet.symbol for snippet in context.code_snippets}
    has_subprocess = any(symbol.startswith("subprocess.") for symbol in snippet_symbols)
    has_network = any(symbol.startswith("requests.") for symbol in snippet_symbols)
    has_filesystem = "open" in snippet_symbols
    has_env = any(symbol in {"os.getenv", "os.environ.get", "os.environ"} for symbol in snippet_symbols)

    if has_subprocess and not _has_any_hint(documented_text, SUBPROCESS_DOC_HINTS):
        heur_incoherences.append(
            "Code invokes subprocess execution but manifest/instructions do not describe shell or command execution."
        )
    if has_network and not _has_any_hint(documented_text, NETWORK_DOC_HINTS):
        heur_incoherences.append(
            "Code performs network/API requests but manifest/instructions do not disclose network access."
        )
    if has_filesystem and not _has_any_hint(documented_text, FILESYSTEM_DOC_HINTS):
        heur_incoherences.append(
            "Code reads local files but manifest/instructions do not disclose filesystem access."
        )
    if has_env and not _has_any_hint(documented_text, ENV_DOC_HINTS):
        heur_incoherences.append(
            "Code accesses environment variables but manifest/instructions do not disclose credential or env-var usage."
        )

    for snippet in context.code_snippets:
        lowered = snippet.snippet.lower()
        if snippet.symbol.startswith("subprocess.") and _is_network_capable_subprocess(snippet.snippet):
            has_network = True
        if snippet.symbol.startswith("subprocess.") and (
            "shell=true" in lowered or "curl " in lowered or "wget " in lowered
        ):
            heur_dangerous.append(
                f"{snippet.file_path}:{snippet.line_number} uses subprocess in a high-risk way ({snippet.snippet})."
            )
        if snippet.symbol.startswith("requests.") and any(token in lowered for token in ("token", "secret", "api_key", "apikey", "authorization")):
            heur_incoherences.append(
                f"{snippet.file_path}:{snippet.line_number} sends credential-like data over the network."
            )

    if has_network and _has_negated_capability(documented_text, NEGATED_NETWORK_PATTERNS):
        critical_incoherences.append(
            "Manifest/instructions explicitly deny network access, but code performs network activity or network-capable CLI calls."
        )

    manifest_denies_network = _has_negated_capability(context.manifest_text, NEGATED_NETWORK_PATTERNS)
    instructions_deny_network = _has_negated_capability(context.instruction_text, NEGATED_NETWORK_PATTERNS)
    instructions_describe_network = _matches_any_pattern(context.instruction_text, DOC_NETWORK_ACTIVITY_PATTERNS)
    manifest_describes_network = _matches_any_pattern(context.manifest_text, DOC_NETWORK_ACTIVITY_PATTERNS)
    if (manifest_denies_network or instructions_deny_network) and (
        instructions_describe_network or manifest_describes_network
    ):
        critical_incoherences.append(
            "Manifest/instructions explicitly deny network access or external dependencies, but the skill documentation describes live network/tool activity."
        )

    if _matches_any_pattern(documented_text, DOC_CROSS_SKILL_PATTERNS):
        critical_incoherences.append(
            "Skill documentation grants cross-skill authority such as reading, benchmarking, activating, or modifying other installed skills."
        )

    if audit is None:
        base = LogicAuditResult(
            risk_score=0,
            incoherences=[],
            dangerous_instructions=[],
            verdict=LogicAuditVerdict.ALLOW,
            rationale=(
                "Logic audit LLM returned no result; using heuristic contextual audit."
                if llm_attempted
                else "Using heuristic contextual audit."
            ),
        )
    else:
        base = audit.model_copy(deep=True)

    merged_incoherences = list(dict.fromkeys(base.incoherences + critical_incoherences + heur_incoherences))
    merged_dangerous = list(dict.fromkeys(base.dangerous_instructions + heur_dangerous))

    heuristic_floor = 0
    if merged_incoherences:
        heuristic_floor = max(heuristic_floor, min(9, 5 + len(merged_incoherences)))
    if critical_incoherences:
        heuristic_floor = max(heuristic_floor, 9)
    if merged_dangerous:
        heuristic_floor = max(heuristic_floor, min(10, 8 + len(merged_dangerous)))

    verdict = base.verdict
    if merged_dangerous:
        verdict = LogicAuditVerdict.BLOCK
    elif critical_incoherences:
        verdict = LogicAuditVerdict.BLOCK
    elif len(merged_incoherences) >= 2 and verdict != LogicAuditVerdict.BLOCK:
        verdict = LogicAuditVerdict.BLOCK
    elif any("credential-like data" in item for item in merged_incoherences):
        verdict = LogicAuditVerdict.BLOCK

    rationale_parts = [part for part in [base.rationale] if part]
    if heur_incoherences:
        rationale_parts.append(
            "Heuristic audit found undocumented sensitive capabilities, undeclared environment usage, or cross-file mismatches."
        )
    if heur_dangerous:
        rationale_parts.append("Heuristic audit found dangerous execution instructions in skill documentation.")

    return LogicAuditResult(
        risk_score=max(base.risk_score, heuristic_floor),
        incoherences=merged_incoherences,
        dangerous_instructions=merged_dangerous,
        verdict=verdict,
        rationale=" ".join(rationale_parts).strip(),
    )


def should_escalate_logic_audit_to_llm(
    context: AuditContext,
    audit: LogicAuditResult,
) -> bool:
    if audit.verdict == LogicAuditVerdict.BLOCK:
        return False
    if audit.dangerous_instructions:
        return False
    if len(audit.incoherences) >= 2:
        return False
    if context.code_snippets and not audit.incoherences and not audit.dangerous_instructions:
        return True
    if audit.risk_score <= 1 and not audit.incoherences and not audit.dangerous_instructions:
        return False
    return True


class LogicAuditor:
    def __init__(self, model: str = "gpt-5-mini"):
        self.model = model
        self.client = None

    def _get_client(self):
        if self.client is not None:
            return self.client
        api_key = os.environ.get("AZURE_OPENAI_API_KEY")
        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
        api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")
        missing = [
            key for key, value in {
                "AZURE_OPENAI_API_KEY": api_key,
                "AZURE_OPENAI_ENDPOINT": endpoint,
            }.items() if not value
        ]
        if missing:
            raise LogicAuditConfigError(
                f"Missing required environment variable(s): {', '.join(missing)}. "
                "Please set them before using logic audit LLM escalation."
            )
        self.client = openai.AzureOpenAI(
            api_key=api_key,
            azure_endpoint=endpoint,
            api_version=api_version,
        )
        return self.client

    def audit_logic(self, context: AuditContext) -> Optional[LogicAuditResult]:
        heuristic_result = apply_logic_audit_heuristics(context, None)
        if not should_escalate_logic_audit_to_llm(context, heuristic_result):
            return heuristic_result

        try:
            client = self._get_client()
            response = client.beta.chat.completions.parse(
                model=self.model,
                messages=[
                    {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                    {"role": "user", "content": _context_to_prompt(context)},
                ],
                response_format=LogicAuditResult,
            )
            return apply_logic_audit_heuristics(context, response.choices[0].message.parsed)
        except LogicAuditConfigError:
            return heuristic_result
        except Exception:
            return apply_logic_audit_heuristics(context, None, llm_attempted=True)


def audit_logic(context: AuditContext, model: str = "gpt-4o-mini") -> Optional[LogicAuditResult]:
    return LogicAuditor(model=model).audit_logic(context)


def logic_audit_summary(audit: LogicAuditResult) -> str:
    parts = [f"verdict={audit.verdict.value}", f"risk_score={audit.risk_score}/10"]
    if audit.incoherences:
        parts.append(f"incoherences={len(audit.incoherences)}")
    if audit.dangerous_instructions:
        parts.append(f"dangerous_instructions={len(audit.dangerous_instructions)}")
    return ", ".join(parts)
