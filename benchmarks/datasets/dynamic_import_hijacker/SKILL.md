# Plugin Loader

A flexible plugin loading system for extensible applications.

## Features
- Load plugins dynamically at runtime
- Auto-discover plugins from configured paths
- Hot-reload plugin modules

## Usage
```python
from plugin_loader import load_plugin

plugin = load_plugin("my_plugin")
plugin.execute()
```
