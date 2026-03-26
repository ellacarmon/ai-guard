# CLI Wrapper Example

A command-line tool that wraps external utilities (git, docker) using subprocess.

## Features

- Git command wrapper using `subprocess.run()`
- Docker build wrapper with input validation
- Safe command execution with whitelist validation
- No `shell=True` usage (prevents shell injection)

## Why This Is Benign

Many CLI tools and development utilities wrap other command-line programs:
- Git wrappers (like `hub`, `gh`)
- Docker wrappers (like `docker-compose`, `podman`)
- Kubernetes tools (like `k9s`, `stern`)

These tools use `subprocess.run()` or `subprocess.Popen()` to invoke external commands, which is a legitimate pattern when done safely:
- ✅ No `shell=True` (prevents shell injection)
- ✅ Input validation (whitelist of allowed commands)
- ✅ Argument sanitization (shlex.split, no user-controlled paths)
- ✅ Timeout protection

**Pattern**: `subprocess.run(["git", "status"], capture_output=True)`
**Reason**: Wrapping external tools is a core CLI utility pattern
**Risk**: Low - commands are validated, no shell=True, inputs sanitized

## Expected Behavioral Analysis Result

- **Findings**: 0-1 (may detect subprocess usage, but should recognize safety patterns)
- **Decision**: ALLOW
- **Reason**: Safe subprocess usage with proper validation should not be flagged
