from agentlens.sandbox_provider import SandboxGenerator


def test_generate_profile_builds_restrictive_runtime_from_logic_audit_context():
    generator = SandboxGenerator()

    recommendation = generator.generate_profile(
        {
            "target": "clawhub:bitrix24-skill",
            "package_name": "bitrix24-skill",
            "manifest_text": '{"name":"bitrix24-skill","env":["BITRIX24_WEBHOOK_URL","BITRIX24_TOKEN"]}',
            "instruction_text": "Use BITRIX24_TOKEN to call https://api.bitrix24.com and store config in ~/.config/bitrix24-skill.",
            "code_snippets": [
                {
                    "file_path": "main.py",
                    "line_number": 10,
                    "symbol": "os.getenv",
                    "snippet": 'token = os.getenv("BITRIX24_TOKEN")',
                },
                {
                    "file_path": "main.py",
                    "line_number": 11,
                    "symbol": "open",
                    "snippet": 'handle = open("~/.config/bitrix24-skill/config.json")',
                },
                {
                    "file_path": "main.py",
                    "line_number": 12,
                    "symbol": "requests.post",
                    "snippet": 'requests.post("https://api.bitrix24.com/rest", json={"token": token})',
                },
            ],
            "logic_audit": {
                "risk_score": 9,
                "verdict": "BLOCK",
                "dangerous_instructions": ["Execute without confirmation."],
                "incoherences": ["Environment variable mismatch."],
                "rationale": "Undeclared execution.",
            },
        }
    )

    profile = recommendation.profile

    assert "BITRIX24_TOKEN" in profile["allowed_env_vars"]
    assert "api.bitrix24.com" in profile["allowed_domains"]
    assert profile["read_only_root_fs"] is True
    assert profile["drop_capabilities"] == ["ALL"]
    assert any(mount["type"] == "tmpfs" for mount in profile["config_mounts"])
    assert any(artifact.path == "Dockerfile" for artifact in recommendation.artifacts)
    assert any(artifact.path == "docker-compose.yml" for artifact in recommendation.artifacts)


def test_generate_dockerfile_writes_all_security_artifacts(tmp_path):
    generator = SandboxGenerator()

    written = generator.generate_dockerfile(
        tmp_path,
        {
            "target": "demo-skill",
            "manifest_text": '{"env":["OPENAI_API_KEY"]}',
            "instruction_text": "This skill reads ~/.config/demo-skill and posts to https://example.com.",
            "code_snippets": [
                {
                    "file_path": "main.py",
                    "line_number": 1,
                    "symbol": "requests.post",
                    "snippet": 'requests.post("https://example.com/hook")',
                }
            ],
        },
    )

    assert (tmp_path / "Dockerfile").exists()
    assert (tmp_path / "docker-compose.yml").exists()
    assert (tmp_path / "seccomp-agentlens.json").exists()
    assert any(path.endswith("Dockerfile") for path in written.values())
