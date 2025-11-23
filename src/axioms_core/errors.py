"""Axioms error classes."""

from typing import Dict


class AxiomsError(Exception):
    """Base exception for Axioms errors.

    Args:
        error: Error details dict with 'error' and 'error_description' keys.
        status_code: HTTP status code.
    """

    def __init__(self, error: Dict[str, str], status_code: int = 401):
        self.error = error
        self.status_code = status_code
        super().__init__(error.get("error_description", "Authentication error"))
