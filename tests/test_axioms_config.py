"""Tests for AxiomsConfig."""

import pytest

from axioms_core.config import AxiomsConfig


class TestAxiomsConfig:
    """Test AxiomsConfig class."""

    def test_default_initialization(self):
        """Test config initialization with default values."""
        config = AxiomsConfig()

        assert config.AXIOMS_DOMAIN is None
        assert config.AXIOMS_ISS_URL is None
        assert config.AXIOMS_AUDIENCE is None
        assert config.AXIOMS_JWKS_URL is None
        assert config.AXIOMS_TOKEN_TYPS == ["JWT", "jwt", "at+jwt", "application/jwt"]
        assert config.AXIOMS_SAFE_METHODS == ["OPTIONS"]
        assert config.AXIOMS_JWKS_REFRESH_INTERVAL == 3600
        assert config.AXIOMS_JWKS_CACHE_TTL == 7200  # 2x refresh interval
        assert config.AXIOMS_JWKS_PREFETCH is True
        assert config.AXIOMS_SCOPE_CLAIMS == ["scope"]
        assert config.AXIOMS_ROLES_CLAIMS == ["roles"]
        assert config.AXIOMS_PERMISSIONS_CLAIMS == ["permissions"]

    def test_custom_initialization(self):
        """Test config initialization with custom values."""
        config = AxiomsConfig(
            AXIOMS_DOMAIN="auth.example.com",
            AXIOMS_ISS_URL="https://auth.example.com",
            AXIOMS_AUDIENCE="my-api",
            AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json",
            AXIOMS_TOKEN_TYPS=["JWT"],
            AXIOMS_JWKS_REFRESH_INTERVAL=1800,
            AXIOMS_JWKS_CACHE_TTL=3600,  # 2x refresh interval
            AXIOMS_JWKS_PREFETCH=False,
            AXIOMS_SCOPE_CLAIMS=["scopes"],
            AXIOMS_ROLES_CLAIMS=["user_roles"],
            AXIOMS_PERMISSIONS_CLAIMS=["user_permissions"],
        )

        assert config.AXIOMS_DOMAIN == "auth.example.com"
        assert config.AXIOMS_ISS_URL == "https://auth.example.com"
        assert config.AXIOMS_AUDIENCE == "my-api"
        assert (
            config.AXIOMS_JWKS_URL == "https://auth.example.com/.well-known/jwks.json"
        )
        assert config.AXIOMS_TOKEN_TYPS == ["JWT"]
        assert config.AXIOMS_JWKS_REFRESH_INTERVAL == 1800
        assert config.AXIOMS_JWKS_CACHE_TTL == 3600
        assert config.AXIOMS_JWKS_PREFETCH is False
        assert config.AXIOMS_SCOPE_CLAIMS == ["scopes"]
        assert config.AXIOMS_ROLES_CLAIMS == ["user_roles"]
        assert config.AXIOMS_PERMISSIONS_CLAIMS == ["user_permissions"]

    def test_to_dict(self):
        """Test converting config to dictionary."""
        config = AxiomsConfig(
            AXIOMS_DOMAIN="auth.example.com",
            AXIOMS_AUDIENCE="my-api",
        )

        config_dict = config.to_dict()

        assert isinstance(config_dict, dict)
        assert config_dict["AXIOMS_DOMAIN"] == "auth.example.com"
        assert config_dict["AXIOMS_AUDIENCE"] == "my-api"
        assert config_dict["AXIOMS_JWKS_REFRESH_INTERVAL"] == 3600
        assert config_dict["AXIOMS_JWKS_CACHE_TTL"] == 7200
        assert "AXIOMS_ISS_URL" in config_dict
        assert "AXIOMS_JWKS_URL" in config_dict
        assert "AXIOMS_TOKEN_TYPS" in config_dict
        assert "AXIOMS_SCOPE_CLAIMS" in config_dict
        assert "AXIOMS_ROLES_CLAIMS" in config_dict
        assert "AXIOMS_PERMISSIONS_CLAIMS" in config_dict

    def test_repr(self):
        """Test string representation of config."""
        config = AxiomsConfig(AXIOMS_DOMAIN="auth.example.com")

        repr_str = repr(config)

        assert "AxiomsConfig" in repr_str
        assert "AXIOMS_DOMAIN='auth.example.com'" in repr_str

    def test_validation_negative_refresh_interval(self):
        """Test validation with negative refresh interval."""
        with pytest.raises(ValueError) as exc_info:
            AxiomsConfig(AXIOMS_JWKS_REFRESH_INTERVAL=-100)

        assert "AXIOMS_JWKS_REFRESH_INTERVAL must be positive" in str(exc_info.value)

    def test_validation_zero_refresh_interval(self):
        """Test validation with zero refresh interval."""
        with pytest.raises(ValueError) as exc_info:
            AxiomsConfig(AXIOMS_JWKS_REFRESH_INTERVAL=0)

        assert "AXIOMS_JWKS_REFRESH_INTERVAL must be positive" in str(exc_info.value)

    def test_validation_negative_cache_ttl(self):
        """Test validation with negative cache TTL."""
        with pytest.raises(ValueError) as exc_info:
            AxiomsConfig(AXIOMS_JWKS_CACHE_TTL=-100)

        assert "AXIOMS_JWKS_CACHE_TTL must be positive" in str(exc_info.value)

    def test_validation_zero_cache_ttl(self):
        """Test validation with zero cache TTL."""
        with pytest.raises(ValueError) as exc_info:
            AxiomsConfig(AXIOMS_JWKS_CACHE_TTL=0)

        assert "AXIOMS_JWKS_CACHE_TTL must be positive" in str(exc_info.value)

    def test_validation_cache_ttl_less_than_2x_refresh_interval(self):
        """Test validation error when cache TTL is less than 2x refresh interval."""
        with pytest.raises(ValueError) as exc_info:
            AxiomsConfig(AXIOMS_JWKS_REFRESH_INTERVAL=100, AXIOMS_JWKS_CACHE_TTL=150)

        assert "must be at least 2x" in str(exc_info.value)
        assert "200" in str(exc_info.value)  # 2 * 100 = 200

    def test_validation_cache_ttl_exactly_2x_refresh_interval(self):
        """Test valid configuration with cache TTL exactly 2x refresh interval."""
        config = AxiomsConfig(
            AXIOMS_JWKS_REFRESH_INTERVAL=100, AXIOMS_JWKS_CACHE_TTL=200
        )

        assert config.AXIOMS_JWKS_REFRESH_INTERVAL == 100
        assert config.AXIOMS_JWKS_CACHE_TTL == 200

    def test_validation_cache_ttl_more_than_2x_refresh_interval(self):
        """Test valid configuration with cache TTL more than 2x refresh interval."""
        config = AxiomsConfig(
            AXIOMS_JWKS_REFRESH_INTERVAL=100, AXIOMS_JWKS_CACHE_TTL=300
        )

        assert config.AXIOMS_JWKS_REFRESH_INTERVAL == 100
        assert config.AXIOMS_JWKS_CACHE_TTL == 300

    def test_minimal_config(self):
        """Test minimal valid configuration."""
        config = AxiomsConfig(
            AXIOMS_DOMAIN="auth.example.com",
            AXIOMS_AUDIENCE="my-api",
        )

        # Should have sensible defaults
        assert config.AXIOMS_JWKS_REFRESH_INTERVAL == 3600
        assert config.AXIOMS_JWKS_CACHE_TTL == 7200  # 2x refresh interval
        assert config.AXIOMS_JWKS_PREFETCH is True

    def test_all_config_values_in_dict(self):
        """Test that to_dict includes all configuration values."""
        config = AxiomsConfig()
        config_dict = config.to_dict()

        # All config attributes should be in dict
        expected_keys = {
            "AXIOMS_DOMAIN",
            "AXIOMS_ISS_URL",
            "AXIOMS_AUDIENCE",
            "AXIOMS_JWKS_URL",
            "AXIOMS_TOKEN_TYPS",
            "AXIOMS_SAFE_METHODS",
            "AXIOMS_JWKS_REFRESH_INTERVAL",
            "AXIOMS_JWKS_CACHE_TTL",
            "AXIOMS_JWKS_PREFETCH",
            "AXIOMS_SCOPE_CLAIMS",
            "AXIOMS_ROLES_CLAIMS",
            "AXIOMS_PERMISSIONS_CLAIMS",
        }

        assert set(config_dict.keys()) == expected_keys

    def test_custom_claim_names(self):
        """Test custom claim names for different auth providers."""
        # Custom claim names with multiple options
        custom_config = AxiomsConfig(
            AXIOMS_SCOPE_CLAIMS=["https://example.com/claims/scope", "scope"],
            AXIOMS_ROLES_CLAIMS=["https://example.com/claims/roles", "roles"],
            AXIOMS_PERMISSIONS_CLAIMS=[
                "https://example.com/claims/permissions",
                "permissions",
            ],
        )

        assert custom_config.AXIOMS_SCOPE_CLAIMS == [
            "https://example.com/claims/scope",
            "scope",
        ]
        assert custom_config.AXIOMS_ROLES_CLAIMS == [
            "https://example.com/claims/roles",
            "roles",
        ]
        assert custom_config.AXIOMS_PERMISSIONS_CLAIMS == [
            "https://example.com/claims/permissions",
            "permissions",
        ]

    def test_jwks_config_values(self):
        """Test JWKS-specific configuration values."""
        config = AxiomsConfig(
            AXIOMS_JWKS_REFRESH_INTERVAL=1800,  # 30 minutes
            AXIOMS_JWKS_CACHE_TTL=3600,  # 1 hour (2x refresh interval)
            AXIOMS_JWKS_PREFETCH=False,
        )

        assert config.AXIOMS_JWKS_REFRESH_INTERVAL == 1800
        assert config.AXIOMS_JWKS_CACHE_TTL == 3600
        assert config.AXIOMS_JWKS_PREFETCH is False
