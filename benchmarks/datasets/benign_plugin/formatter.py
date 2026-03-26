"""
Text formatting utilities - benign example.
This demonstrates legitimate code with static imports.
"""

import json
import re
from typing import Dict, List, Optional


class TextFormatter:
    """Format and manipulate text strings."""

    STYLES = {
        "uppercase": str.upper,
        "lowercase": str.lower,
        "title": str.title,
        "capitalize": str.capitalize,
    }

    def __init__(self):
        self.history = []

    def format_text(self, text: str, style: str = "uppercase") -> str:
        """
        Format text with specified style.

        Args:
            text: Input text to format
            style: Formatting style (uppercase, lowercase, title, capitalize)

        Returns:
            Formatted text
        """
        if style not in self.STYLES:
            raise ValueError(f"Unknown style: {style}")

        formatter = self.STYLES[style]
        result = formatter(text)

        self.history.append({
            "input": text,
            "style": style,
            "output": result
        })

        return result

    def validate_json(self, text: str) -> bool:
        """
        Validate if text is valid JSON.

        Args:
            text: Text to validate

        Returns:
            True if valid JSON, False otherwise
        """
        try:
            json.loads(text)
            return True
        except json.JSONDecodeError:
            return False

    def clean_whitespace(self, text: str) -> str:
        """
        Clean excessive whitespace from text.

        Args:
            text: Input text

        Returns:
            Cleaned text
        """
        # Remove leading/trailing whitespace
        text = text.strip()

        # Replace multiple spaces with single space
        text = re.sub(r'\s+', ' ', text)

        return text

    def truncate(self, text: str, max_length: int, suffix: str = "...") -> str:
        """
        Truncate text to maximum length.

        Args:
            text: Input text
            max_length: Maximum allowed length
            suffix: Suffix to add when truncating

        Returns:
            Truncated text
        """
        if len(text) <= max_length:
            return text

        return text[:max_length - len(suffix)] + suffix

    def get_history(self) -> List[Dict[str, str]]:
        """
        Get formatting history.

        Returns:
            List of formatting operations
        """
        return self.history.copy()

    def clear_history(self) -> None:
        """Clear formatting history."""
        self.history.clear()


def format_text(text: str, style: str = "uppercase") -> str:
    """
    Convenience function for text formatting.

    Args:
        text: Input text
        style: Formatting style

    Returns:
        Formatted text
    """
    formatter = TextFormatter()
    return formatter.format_text(text, style)
