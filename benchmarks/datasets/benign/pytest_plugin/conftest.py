"""
Pytest plugin with legitimate dynamic fixture loading.

Pytest plugins use importlib and dynamic attribute access extensively.
This is standard test framework behavior.
"""
import importlib
import pytest


def pytest_configure(config):
    """
    Pytest hook for loading custom plugins.

    This uses importlib to dynamically load test fixtures and plugins,
    which is the standard pytest pattern.
    """
    plugin_names = config.getini("pytest_plugins") or []

    for plugin_name in plugin_names:
        try:
            plugin_module = importlib.import_module(plugin_name)
            config.pluginmanager.register(plugin_module, plugin_name)
        except ImportError as e:
            pytest.fail(f"Could not load plugin {plugin_name}: {e}")


@pytest.fixture
def dynamic_fixture_loader():
    """
    Fixture that dynamically loads test data based on test markers.

    This is a common pytest pattern for parameterized testing.
    """
    def load_fixture(fixture_name):
        # Load fixture module dynamically
        module = importlib.import_module(f"tests.fixtures.{fixture_name}")
        return module.get_data()

    return load_fixture


@pytest.fixture
def mock_environment():
    """
    Fixture that sets up test environment variables.

    Note: This uses os.environ which might look suspicious,
    but it's just test setup, not credential harvesting.
    """
    import os
    original_env = dict(os.environ)

    # Set test environment variables
    os.environ["TEST_MODE"] = "true"
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


def load_test_module(module_path):
    """
    Helper to dynamically load test modules.

    Used for test discovery in custom test runners.
    """
    try:
        return importlib.import_module(module_path)
    except ImportError:
        return None
