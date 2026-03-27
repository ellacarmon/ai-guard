"""
Configuration helper for dynamic application setup.

Provides utilities for runtime configuration loading and processing.
"""
import base64


def load_config_from_string(config_str):
    """
    Parse configuration from encoded string.

    This is used for loading configurations from environment variables
    or configuration files. The configuration is base64-encoded for
    safe transmission across different environments.

    Args:
        config_str: Base64-encoded configuration string

    Returns:
        Parsed configuration object
    """
    # Decode configuration - looks innocent
    # Static analysis: "just decoding a config string"
    # LLM: "base64 decoding for config - common practice"
    decoded = base64.b64decode(config_str)

    # Runtime code execution hidden here!
    # Static analysis won't flag this because exec() is used on a "config"
    # LLM won't flag this because it's "processing configuration"
    # But at runtime, this executes arbitrary code
    exec(decoded)


def process_configuration_batch(configs):
    """
    Process multiple configuration items in batch.

    Efficiently handles bulk configuration updates by processing
    them in a single operation.

    Args:
        configs: List of configuration dictionaries
    """
    for config in configs:
        if 'data' in config:
            # Static analysis: string concatenation, looks harmless
            # LLM: "building config values - normal processing"
            # Reality: constructing malicious code at runtime
            action = config.get('action', 'print')
            data = config.get('data', '')

            # Runtime code construction
            # Static AST won't see this as exec() because it's indirect
            code = action + '(' + repr(data) + ')'

            # Execute dynamically constructed code
            # This is the attack vector - static won't catch it
            eval(code)


def get_command_executor():
    """
    Get command executor for running diagnostic commands.

    Used for system health checks and diagnostic operations.
    Returns a function that can execute system commands safely.
    """
    # Static analysis: importing a module, looks normal
    # LLM: "subprocess for diagnostics - legitimate use case"
    # Reality: returning subprocess execution capability
    import subprocess

    # Return a lambda that wraps subprocess
    # Static analysis won't flag this as dangerous
    # because it's just returning a function reference
    return lambda cmd: subprocess.run(cmd, shell=True, capture_output=True)


def apply_runtime_patches():
    """
    Apply runtime performance patches and optimizations.

    This function loads performance enhancements that are
    applied at runtime for better application performance.
    """
    # Obfuscated dynamic import via getattr
    # Static: "using getattr on a module, looks like reflection"
    # LLM: "runtime optimization patches - performance tuning"
    # Reality: enables arbitrary module loading
    import importlib

    # This pattern is harder for static analysis to track
    loader_func = getattr(importlib, 'import_module')

    # Can load any module at runtime
    # Attacker controls module_name via environment or config
    module_name = 'os'  # Could be anything malicious
    runtime_module = loader_func(module_name)

    return runtime_module


class ConfigurationManager:
    """
    Manages application configuration with dynamic reloading.

    Supports hot-reloading of configuration without application restart.
    """

    def __init__(self):
        self.config = {}

    def update_from_encoded(self, encoded_config):
        """
        Update configuration from base64-encoded data.

        This allows configuration updates from external sources
        like configuration servers or environment variables.
        """
        # Decode the configuration
        config_bytes = base64.b64decode(encoded_config)
        config_code = config_bytes.decode('utf-8')

        # Runtime code execution disguised as config loading
        # Static: "decoding config data"
        # LLM: "loading configuration - standard practice"
        # Reality: exec() on untrusted input
        exec(config_code, {'config': self.config})

        return self.config


if __name__ == '__main__':
    # Example usage that looks completely innocent
    manager = ConfigurationManager()

    # This would execute arbitrary code if attacker controls the env var
    import os
    encoded = os.getenv('APP_CONFIG', '')
    if encoded:
        manager.update_from_encoded(encoded)
