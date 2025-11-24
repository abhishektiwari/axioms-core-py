"""Axioms Core - Shared JWT authentication and authorization logic.

This package provides framework-agnostic JWT token validation, JWKS key retrieval,
and claim extraction that can be used by Axioms packages for FastAPI, Django, and Flask.
"""

from .config import AxiomsConfig
from .errors import AxiomsError
from .helper import (
    ALLOWED_ALGORITHMS,
    check_claims,
    check_permissions,
    check_roles,
    check_scopes,
    check_token_validity,
    get_claim_from_token,
    get_claim_names,
    get_expected_issuer,
    get_jwks_url,
    get_key_from_jwks_json,
    get_token_permissions,
    get_token_roles,
    get_token_scopes,
    validate_token_header,
)
from .jwks import (
    AsyncJWKSManager,
    JWKSManager,
    initialize_async_jwks_manager,
    initialize_jwks_manager,
    shutdown_async_jwks_manager,
    shutdown_jwks_manager,
)

__all__ = [
    "ALLOWED_ALGORITHMS",
    "AsyncJWKSManager",
    "AxiomsConfig",
    "AxiomsError",
    "JWKSManager",
    "check_claims",
    "check_permissions",
    "check_roles",
    "check_scopes",
    "check_token_validity",
    "get_claim_from_token",
    "get_claim_names",
    "get_expected_issuer",
    "get_jwks_url",
    "get_key_from_jwks_json",
    "get_token_permissions",
    "get_token_roles",
    "get_token_scopes",
    "initialize_async_jwks_manager",
    "initialize_jwks_manager",
    "shutdown_async_jwks_manager",
    "shutdown_jwks_manager",
    "validate_token_header",
]

try:
    from ._version import version as __version__
except ImportError:
    __version__ = "unknown"
