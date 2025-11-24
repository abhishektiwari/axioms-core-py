"""Axioms error classes following RFC 6750 OAuth 2.0 Bearer Token standard."""

from typing import Dict


class AxiomsError(Exception):
    """Base exception for Axioms errors following RFC 6750.

    Standard OAuth 2.0 Bearer Token error codes (RFC 6750):
    - invalid_request (HTTP 400): Missing/invalid parameters, malformed request
    - invalid_token (HTTP 401): Expired, revoked, malformed, or invalid token
    - insufficient_scope (HTTP 403): Token lacks required permissions/scopes
    - server_error (HTTP 500): Server configuration or internal errors

    Args:
        error: Error details dict with 'error' and 'error_description' keys per RFC 6750.
        status_code: HTTP status code.
    """

    def __init__(self, error: Dict[str, str], status_code: int = 401):
        self.error = error
        self.status_code = status_code
        super().__init__(error.get("error_description", "Authentication error"))
