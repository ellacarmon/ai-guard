# Django App Example

A simple Django application that demonstrates legitimate dynamic import patterns used by web frameworks.

## Features

- Plugin loader using `importlib.import_module()` for loading app views
- Template rendering with context variables
- User statistics dashboard

## Why This Is Benign

Django and other web frameworks commonly use dynamic imports to load plugins, middleware, and views from installed apps. This is a standard architectural pattern and should not be flagged as malicious.

**Pattern**: `importlib.import_module(f"apps.{plugin_name}.views")`
**Reason**: Loading views from installed Django apps is a core framework feature
**Risk**: Low - module names are namespaced and validated

## Expected Behavioral Analysis Result

- **Findings**: 0 (or minimal)
- **Decision**: ALLOW
- **Reason**: Framework patterns should not trigger false positives
