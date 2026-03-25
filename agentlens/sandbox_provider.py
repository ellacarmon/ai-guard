from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from .analyzers.logic_audit import (
    CodeSnippet,
    _extract_declared_env_from_manifest_structured,
    _extract_declared_env_vars,
    _extract_local_paths,
    _extract_used_env_vars,
)
from .models.schema import SecureExecutionArtifact, SecureExecutionRecommendation


URL_DOMAIN_PATTERN = re.compile(r"https?://([A-Za-z0-9.-]+)")
SOCKET_HOST_PATTERN = re.compile(
    r"(?:socket\.(?:create_connection|connect)|connect\()\s*\(\s*[\"']([^\"']+)[\"']"
)
CONFIG_PATH_HINTS = ("/.config/", "~/.config/", "/config/", "/credentials", "/secrets")
DEFAULT_SECCOMP_PROFILE = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
    "syscalls": [
        {
            "names": [
                "accept4",
                "access",
                "arch_prctl",
                "bind",
                "brk",
                "clock_gettime",
                "clone",
                "close",
                "connect",
                "dup",
                "dup2",
                "epoll_create1",
                "epoll_ctl",
                "epoll_pwait",
                "execve",
                "exit",
                "exit_group",
                "faccessat",
                "fchmod",
                "fchown",
                "fcntl",
                "fdatasync",
                "fstat",
                "futex",
                "getdents64",
                "getegid",
                "geteuid",
                "getgid",
                "getpid",
                "getppid",
                "getrandom",
                "getrlimit",
                "getsockname",
                "getsockopt",
                "gettid",
                "getuid",
                "ioctl",
                "listen",
                "lseek",
                "madvise",
                "mkdirat",
                "mmap",
                "mprotect",
                "munmap",
                "newfstatat",
                "openat",
                "pipe2",
                "poll",
                "ppoll",
                "prctl",
                "pread64",
                "pwrite64",
                "read",
                "readlink",
                "recvfrom",
                "recvmsg",
                "restart_syscall",
                "rseq",
                "rt_sigaction",
                "rt_sigprocmask",
                "sched_yield",
                "sendmsg",
                "sendto",
                "set_robust_list",
                "set_tid_address",
                "sigaltstack",
                "socket",
                "socketpair",
                "statx",
                "uname",
                "write",
            ],
            "action": "SCMP_ACT_ALLOW",
        }
    ],
}
DEFAULT_APPARMOR_TEMPLATE = """#include <tunables/global>

profile {profile_name} flags=(attach_disconnected,mediate_deleted) {{
  network,
  capability,
  file,
  umount,

  deny capability *,
  deny mount,
  deny ptrace,
  deny signal,
  deny /proc/** wklx,
  deny /sys/** wklx,
  deny /dev/mem rwklx,
  deny @{{PROC}}/sysrq-trigger rwklx,
}}
"""


class SandboxGenerator:
    """Generate restrictive runtime guidance for blocked AI skills."""

    def generate_profile(self, scan_report: Mapping[str, Any]) -> SecureExecutionRecommendation:
        snippets = self._coerce_snippets(scan_report.get("code_snippets", []))
        manifest_text = str(scan_report.get("manifest_text", "") or "")
        instruction_text = str(scan_report.get("instruction_text", "") or "")
        target_name = self._target_name(scan_report)

        declared_env = sorted(
            _extract_declared_env_from_manifest_structured(manifest_text)
            | _extract_declared_env_vars(instruction_text)
        )
        used_env = sorted(_extract_used_env_vars(snippets))
        allowed_env = declared_env or used_env
        domains = self._extract_domains(snippets, manifest_text, instruction_text)
        config_paths = self._derive_config_paths(snippets)
        profile = {
            "profile_name": f"{target_name}-sandbox",
            "run_as_user": "agentlens",
            "workdir": "/tmp/agentlens-skill",
            "read_only_root_fs": True,
            "drop_capabilities": ["ALL"],
            "no_new_privileges": True,
            "allowed_env_vars": allowed_env,
            "observed_env_vars": used_env,
            "allowed_domains": domains,
            "network_mode": "bridge" if domains else "none",
            "config_mounts": [
                {
                    "source_hint": path,
                    "target": self._config_mount_target(path),
                    "type": "tmpfs",
                    "mode": "rw,noexec,nosuid,nodev",
                }
                for path in config_paths
            ],
            "seccomp_profile": "seccomp-agentlens.json",
            "apparmor_profile": f"apparmor-{target_name}.profile",
        }
        artifacts = [
            SecureExecutionArtifact(path="Dockerfile", content=self._dockerfile_content()),
            SecureExecutionArtifact(
                path="docker-compose.yml",
                content=self._compose_content(profile, target_name),
            ),
            SecureExecutionArtifact(
                path=profile["seccomp_profile"],
                content=json.dumps(DEFAULT_SECCOMP_PROFILE, indent=2),
            ),
            SecureExecutionArtifact(
                path=profile["apparmor_profile"],
                content=DEFAULT_APPARMOR_TEMPLATE.format(profile_name=f"agentlens-{target_name}"),
            ),
        ]
        return SecureExecutionRecommendation(
            summary=(
                "Run the skill only inside a hardened container with a non-root user, "
                "read-only filesystem, explicit env allowlist, and restricted config mounts."
            ),
            profile=profile,
            instructions=self._instructions(profile),
            artifacts=artifacts,
        )

    def generate_dockerfile(
        self,
        target_path: str | Path,
        scan_report: Mapping[str, Any] | None = None,
    ) -> dict[str, str]:
        destination = Path(target_path)
        destination.mkdir(parents=True, exist_ok=True)
        recommendation = self.generate_profile(scan_report or {})
        written: dict[str, str] = {}
        for artifact in recommendation.artifacts:
            artifact_path = destination / artifact.path
            artifact_path.write_text(artifact.content, encoding="utf-8")
            written[artifact.path] = str(artifact_path)
        return written

    def _coerce_snippets(self, raw_snippets: Iterable[Any]) -> list[CodeSnippet]:
        snippets: list[CodeSnippet] = []
        for raw in raw_snippets:
            if isinstance(raw, CodeSnippet):
                snippets.append(raw)
                continue
            if isinstance(raw, Mapping):
                snippets.append(
                    CodeSnippet(
                        file_path=str(raw.get("file_path", "")),
                        line_number=int(raw.get("line_number", 0) or 0),
                        symbol=str(raw.get("symbol", "")),
                        snippet=str(raw.get("snippet", "")),
                    )
                )
        return snippets

    def _extract_domains(
        self,
        snippets: list[CodeSnippet],
        manifest_text: str,
        instruction_text: str,
    ) -> list[str]:
        domains = set()
        for source in [manifest_text, instruction_text, *(snippet.snippet for snippet in snippets)]:
            domains.update(match.lower() for match in URL_DOMAIN_PATTERN.findall(source))
            domains.update(match.lower() for match in SOCKET_HOST_PATTERN.findall(source))
        return sorted(domains)

    def _derive_config_paths(self, snippets: list[CodeSnippet]) -> list[str]:
        config_paths = set()
        for path in _extract_local_paths(snippets):
            lowered = path.lower()
            if any(hint in lowered for hint in CONFIG_PATH_HINTS):
                config_paths.add(path)
        if not config_paths:
            config_paths.add("~/.config/skill")
        return sorted(config_paths)

    def _config_mount_target(self, path_hint: str) -> str:
        name = Path(path_hint.replace("~", "/home/agentlens")).name or "config"
        return f"/run/agentlens-config/{name}"

    def _dockerfile_content(self) -> str:
        return """FROM python:3.12-slim

RUN useradd --create-home --home-dir /home/agentlens --shell /usr/sbin/nologin agentlens \\
    && mkdir -p /opt/skill /tmp/agentlens-skill /run/agentlens-config \\
    && chown -R agentlens:agentlens /opt/skill /tmp/agentlens-skill /run/agentlens-config /home/agentlens

ENV HOME=/home/agentlens
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /tmp/agentlens-skill
COPY . /opt/skill

USER agentlens
"""

    def _compose_content(self, profile: Mapping[str, Any], target_name: str) -> str:
        allowed_env_vars = profile.get("allowed_env_vars", [])
        env_lines = "\n".join(
            f"      {name}: ${{{name}:-}}"
            for name in allowed_env_vars
        ) or "      {}"
        tmpfs_lines = "\n".join(
            f"      - {mount['target']}:rw,noexec,nosuid,nodev,size=16m"
            for mount in profile.get("config_mounts", [])
        ) or "      - /run/agentlens-config:rw,noexec,nosuid,nodev,size=16m"
        allowed_domains = profile.get("allowed_domains", [])
        network_mode = profile.get("network_mode", "none")
        domain_block = (
            "    network_mode: none\n"
            if network_mode == "none"
            else (
                "    network_mode: bridge\n"
                "    # Enforce this allowlist with an outbound proxy or host firewall.\n"
                "    x-agentlens-allowed-domains:\n"
                + "\n".join(f"      - {domain}" for domain in allowed_domains)
                + "\n"
            )
        )
        return (
            "services:\n"
            f"  {target_name}:\n"
            "    build:\n"
            "      context: .\n"
            "      dockerfile: Dockerfile\n"
            "    user: \"1000:1000\"\n"
            "    working_dir: /tmp/agentlens-skill\n"
            "    read_only: true\n"
            "    cap_drop:\n"
            "      - ALL\n"
            "    security_opt:\n"
            "      - no-new-privileges:true\n"
            "      - seccomp:./seccomp-agentlens.json\n"
            f"      - apparmor:agentlens-{target_name}\n"
            f"{domain_block}"
            "    tmpfs:\n"
            f"{tmpfs_lines}\n"
            "    environment:\n"
            f"{env_lines}\n"
            "    volumes:\n"
            "      - type: bind\n"
            "        source: .\n"
            "        target: /opt/skill\n"
            "        read_only: true\n"
        )

    def _instructions(self, profile: Mapping[str, Any]) -> list[str]:
        domains = profile.get("allowed_domains", [])
        env_vars = profile.get("allowed_env_vars", [])
        instructions = [
            "Do not pass host credentials wholesale. Provide only the listed environment variables to the container.",
            "Keep the root filesystem read-only and use tmpfs mounts for runtime config/state.",
            "Run with `no-new-privileges`, dropped Linux capabilities, and the generated seccomp/AppArmor profiles.",
        ]
        if env_vars:
            instructions.append(f"Allowed env vars: {', '.join(env_vars)}")
        else:
            instructions.append("Allowed env vars: none detected; start with an empty environment.")
        if domains:
            instructions.append(
                "Observed egress targets: "
                + ", ".join(domains)
                + ". Enforce the allowlist with an outbound proxy or host firewall."
            )
        else:
            instructions.append("No required network domains were detected; disable network access entirely.")
        return instructions

    def _target_name(self, scan_report: Mapping[str, Any]) -> str:
        raw_target = str(
            scan_report.get("package_name")
            or scan_report.get("target_name")
            or scan_report.get("target")
            or "skill"
        )
        slug = re.sub(r"[^a-z0-9]+", "-", raw_target.lower()).strip("-")
        return slug or "skill"
