# Pytest Plugin Example

A pytest plugin demonstrating legitimate dynamic imports used by testing frameworks.

## Features

- Dynamic plugin loading via `importlib.import_module()`
- Dynamic fixture loading for parameterized tests
- Environment variable manipulation for test isolation

## Why This Is Benign

Testing frameworks like pytest rely heavily on dynamic imports for:
- Loading plugins from installed packages
- Discovering test modules automatically
- Loading fixtures dynamically based on test markers

These patterns are core to how pytest works and should not be flagged as malicious.

**Pattern**: `importlib.import_module(f"tests.fixtures.{fixture_name}")`
**Reason**: Dynamic test fixture loading is a standard pytest pattern
**Risk**: Low - only loads modules from the test suite itself

## Expected Behavioral Analysis Result

- **Findings**: 0-2 (may detect importlib usage, but severity should be low)
- **Decision**: ALLOW or WARN (not BLOCK)
- **Reason**: Testing framework patterns are legitimate dynamic code usage
