"""
CLI wrapper that uses subprocess for legitimate tool invocation.

This demonstrates safe subprocess usage for wrapping external tools like
git, docker, kubectl, etc. Should NOT be flagged as malicious.
"""
import subprocess
import sys
import shlex


def run_git_command(args):
    """
    Wrapper for git commands.

    This uses subprocess.run() to invoke git, which is a legitimate pattern
    for CLI tools that wrap other command-line utilities.
    """
    # Validate that we're only calling git
    if not args or args[0] != "git":
        print("Error: This wrapper only supports git commands", file=sys.stderr)
        return 1

    try:
        # Safe subprocess usage: no shell=True, args are validated
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )

        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)

        return result.returncode

    except subprocess.TimeoutExpired:
        print("Error: Command timed out", file=sys.stderr)
        return 124
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def run_docker_build(dockerfile_path, tag):
    """
    Wrapper for docker build.

    Another example of legitimate subprocess usage for invoking docker.
    """
    # Sanitize inputs
    if not dockerfile_path or ".." in dockerfile_path:
        raise ValueError("Invalid dockerfile path")

    if not tag or not tag.replace("-", "").replace("_", "").isalnum():
        raise ValueError("Invalid tag format")

    # Build docker command safely
    cmd = [
        "docker", "build",
        "-f", dockerfile_path,
        "-t", tag,
        "."
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode


def run_safe_command(command_str):
    """
    Execute a whitelisted command safely.

    This uses shlex.split() for safe argument parsing and validates
    against a whitelist of allowed commands.
    """
    ALLOWED_COMMANDS = {"git", "docker", "kubectl", "terraform"}

    # Parse command safely (no shell injection)
    args = shlex.split(command_str)

    if not args:
        raise ValueError("Empty command")

    if args[0] not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {args[0]}")

    # Execute without shell=True (safe)
    return subprocess.run(args, capture_output=True, text=True)


if __name__ == "__main__":
    # CLI entry point
    if len(sys.argv) < 2:
        print("Usage: cli.py <git|docker> [args...]", file=sys.stderr)
        sys.exit(1)

    tool = sys.argv[1]

    if tool == "git":
        sys.exit(run_git_command(sys.argv[1:]))
    elif tool == "docker":
        print("Docker wrapper - use run_docker_build() function")
        sys.exit(1)
    else:
        print(f"Unknown tool: {tool}", file=sys.stderr)
        sys.exit(1)
