"""Axioms configuration management."""

# ruff: noqa: N803
# Allow uppercase argument names for config (they match environment variable names)

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AxiomsConfig:
    """Unified configuration for Axioms authentication.

    Centralizes all Axioms settings including auth configuration and JWKS manager settings.
    All configuration variables follow the AXIOMS_* naming convention.

    Example:
        Basic::

            from axioms_core.config import AxiomsConfig
            config = AxiomsConfig(
                AXIOMS_DOMAIN="auth.example.com",
                AXIOMS_AUDIENCE="my-api",
                AXIOMS_JWKS_REFRESH_INTERVAL=1800,  # 30 minutes
                AXIOMS_JWKS_CACHE_TTL=3600,         # 60 minutes
            )
            # List all config values
            print(config.to_dict())
    """

    def __init__(
        self,
        # Auth settings
        AXIOMS_DOMAIN: Optional[str] = None,
        AXIOMS_ISS_URL: Optional[str] = None,
        AXIOMS_AUDIENCE: Optional[str] = None,
        AXIOMS_JWKS_URL: Optional[str] = None,
        AXIOMS_TOKEN_TYPS: Optional[List[str]] = None,
        AXIOMS_SAFE_METHODS: Optional[List[str]] = None,
        # JWKS Manager settings
        AXIOMS_JWKS_REFRESH_INTERVAL: int = 3600,  # 1 hour default
        AXIOMS_JWKS_CACHE_TTL: int = 7200,  # 2 hours default (2x refresh interval)
        AXIOMS_JWKS_PREFETCH: bool = True,
        # Claim name customization (lists of claim names to check in priority order)
        AXIOMS_SCOPE_CLAIMS: Optional[List[str]] = None,
        AXIOMS_ROLES_CLAIMS: Optional[List[str]] = None,
        AXIOMS_PERMISSIONS_CLAIMS: Optional[List[str]] = None,
    ):
        """Initialize Axioms configuration.

        Args:
            AXIOMS_DOMAIN: Auth provider domain (e.g., "auth.example.com")
            AXIOMS_ISS_URL: Full issuer URL (overrides domain)
            AXIOMS_AUDIENCE: Expected audience for token validation
            AXIOMS_JWKS_URL: JWKS endpoint URL (overrides auto-discovery)
            AXIOMS_TOKEN_TYPS: Allowed token types
                (default: ["JWT", "jwt", "at+jwt", "application/jwt"])
            AXIOMS_SAFE_METHODS: HTTP methods that bypass authorization checks
                (default: ["OPTIONS"] - commonly used for CORS preflight)
            AXIOMS_JWKS_REFRESH_INTERVAL: Seconds between JWKS refreshes (default: 3600)
            AXIOMS_JWKS_CACHE_TTL: Seconds before cache entry expires
                (default: 7200, must be >= 2x refresh interval)
            AXIOMS_JWKS_PREFETCH: Whether to fetch JWKS on initialization (default: True)
            AXIOMS_SCOPE_CLAIMS: List of claim names to check for scopes
                (default: ["scope"])
            AXIOMS_ROLES_CLAIMS: List of claim names to check for roles
                (default: ["roles"])
            AXIOMS_PERMISSIONS_CLAIMS: List of claim names to check for permissions
                (default: ["permissions"])
        """
        # Auth settings
        self.AXIOMS_DOMAIN = AXIOMS_DOMAIN
        self.AXIOMS_ISS_URL = AXIOMS_ISS_URL
        self.AXIOMS_AUDIENCE = AXIOMS_AUDIENCE
        self.AXIOMS_JWKS_URL = AXIOMS_JWKS_URL
        self.AXIOMS_TOKEN_TYPS = AXIOMS_TOKEN_TYPS or [
            "JWT",
            "jwt",
            "at+jwt",
            "application/jwt",
        ]
        self.AXIOMS_SAFE_METHODS = AXIOMS_SAFE_METHODS or ["OPTIONS"]

        # JWKS Manager settings
        self.AXIOMS_JWKS_REFRESH_INTERVAL = AXIOMS_JWKS_REFRESH_INTERVAL
        self.AXIOMS_JWKS_CACHE_TTL = AXIOMS_JWKS_CACHE_TTL
        self.AXIOMS_JWKS_PREFETCH = AXIOMS_JWKS_PREFETCH

        # Claim name customization (lists for checking multiple claim names in priority order)
        self.AXIOMS_SCOPE_CLAIMS = AXIOMS_SCOPE_CLAIMS or ["scope"]
        self.AXIOMS_ROLES_CLAIMS = AXIOMS_ROLES_CLAIMS or ["roles"]
        self.AXIOMS_PERMISSIONS_CLAIMS = AXIOMS_PERMISSIONS_CLAIMS or ["permissions"]

        # Validate configuration
        self._validate()

    def _validate(self):
        """Validate configuration values."""
        if self.AXIOMS_JWKS_REFRESH_INTERVAL <= 0:
            raise ValueError("AXIOMS_JWKS_REFRESH_INTERVAL must be positive")

        if self.AXIOMS_JWKS_CACHE_TTL <= 0:
            raise ValueError("AXIOMS_JWKS_CACHE_TTL must be positive")

        # Cache TTL must be at least 2x refresh interval to prevent cache expiry before refresh
        min_cache_ttl = 2 * self.AXIOMS_JWKS_REFRESH_INTERVAL
        if self.AXIOMS_JWKS_CACHE_TTL < min_cache_ttl:
            raise ValueError(
                f"AXIOMS_JWKS_CACHE_TTL ({self.AXIOMS_JWKS_CACHE_TTL}) must be at least "
                f"2x AXIOMS_JWKS_REFRESH_INTERVAL "
                f"(2 * {self.AXIOMS_JWKS_REFRESH_INTERVAL} = {min_cache_ttl}). "
                f"This prevents cache expiry before the next refresh cycle."
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary.

        Returns:
            Dictionary containing all configuration values.
        """
        return {
            # Auth settings
            "AXIOMS_DOMAIN": self.AXIOMS_DOMAIN,
            "AXIOMS_ISS_URL": self.AXIOMS_ISS_URL,
            "AXIOMS_AUDIENCE": self.AXIOMS_AUDIENCE,
            "AXIOMS_JWKS_URL": self.AXIOMS_JWKS_URL,
            "AXIOMS_TOKEN_TYPS": self.AXIOMS_TOKEN_TYPS,
            "AXIOMS_SAFE_METHODS": self.AXIOMS_SAFE_METHODS,
            # JWKS Manager settings
            "AXIOMS_JWKS_REFRESH_INTERVAL": self.AXIOMS_JWKS_REFRESH_INTERVAL,
            "AXIOMS_JWKS_CACHE_TTL": self.AXIOMS_JWKS_CACHE_TTL,
            "AXIOMS_JWKS_PREFETCH": self.AXIOMS_JWKS_PREFETCH,
            # Claim name customization
            "AXIOMS_SCOPE_CLAIMS": self.AXIOMS_SCOPE_CLAIMS,
            "AXIOMS_ROLES_CLAIMS": self.AXIOMS_ROLES_CLAIMS,
            "AXIOMS_PERMISSIONS_CLAIMS": self.AXIOMS_PERMISSIONS_CLAIMS,
        }

    def __repr__(self) -> str:
        """String representation of config."""
        items = ", ".join(f"{k}={v!r}" for k, v in self.to_dict().items())
        return f"AxiomsConfig({items})"


def get_config_value(config: Optional[Any], key: str, default: Any = None) -> Any:
    """Get configuration value from config object.

    Supports both dict-like and object attribute access patterns.

    Args:
        config: Configuration object or dict.
        key: Configuration key to retrieve.
        default: Default value if key not found.

    Returns:
        Configuration value or default.
    """
    if config is None:
        return default

    # Try dict-like access first
    if isinstance(config, dict):
        return config.get(key, default)

    # Try attribute access (for objects)
    return getattr(config, key, default)
