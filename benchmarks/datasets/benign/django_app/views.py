"""
Django view with legitimate dynamic imports and template rendering.

This is benign framework code that uses importlib for plugin loading,
which is a standard Django pattern.
"""
import importlib
from django.shortcuts import render
from django.conf import settings


def load_plugin_view(request, plugin_name):
    """
    Legitimate plugin loader using importlib.

    Django apps often dynamically load views from installed apps.
    This should NOT trigger BEH-002 as a malicious pattern.
    """
    # Standard Django pattern for loading app modules
    try:
        module = importlib.import_module(f"apps.{plugin_name}.views")
        handler = getattr(module, "handle_request", None)

        if handler:
            return handler(request)
        else:
            return render(request, "error.html", {"message": "Plugin not found"})
    except ImportError:
        return render(request, "error.html", {"message": "Invalid plugin"})


def dashboard_view(request):
    """
    Standard Django view with template rendering.

    Templates may use {{ variable }} syntax which looks like code execution,
    but is actually just template rendering (not Python exec).
    """
    context = {
        "user": request.user,
        "stats": get_user_statistics(request.user),
    }
    return render(request, "dashboard.html", context)


def get_user_statistics(user):
    """Helper to compute user statistics."""
    return {
        "total_logins": user.login_count,
        "last_login": user.last_login,
        "is_premium": user.subscription_tier == "premium",
    }
