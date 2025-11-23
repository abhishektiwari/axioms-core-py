"""Tests for configuration helper functions."""

import pytest

from axioms_core.config import get_config_value
from axioms_core.helper import get_expected_issuer, get_jwks_url


class TestGetConfigValue:
    """Test get_config_value function."""

    def test_dict_config(self):
        """Test getting value from dict config."""
        config = {"AXIOMS_AUDIENCE": "test-audience"}
        value = get_config_value(config, "AXIOMS_AUDIENCE")

        assert value == "test-audience"

    def test_object_config(self):
        """Test getting value from object config."""

        class Config:
            AXIOMS_AUDIENCE = "test-audience"

        config = Config()
        value = get_config_value(config, "AXIOMS_AUDIENCE")

        assert value == "test-audience"

    def test_missing_key_dict(self):
        """Test getting missing key from dict config."""
        config = {"AXIOMS_AUDIENCE": "test-audience"}
        value = get_config_value(config, "AXIOMS_MISSING", default="default-value")

        assert value == "default-value"

    def test_missing_key_object(self):
        """Test getting missing key from object config."""

        class Config:
            AXIOMS_AUDIENCE = "test-audience"

        config = Config()
        value = get_config_value(config, "AXIOMS_MISSING", default="default-value")

        assert value == "default-value"

    def test_none_config(self):
        """Test getting value from None config."""
        value = get_config_value(None, "AXIOMS_AUDIENCE", default="default-value")

        assert value == "default-value"

    def test_no_default(self):
        """Test getting missing key without default."""
        config = {}
        value = get_config_value(config, "AXIOMS_MISSING")

        assert value is None


class TestGetExpectedIssuer:
    """Test get_expected_issuer function."""

    def test_explicit_issuer_url(self):
        """Test with explicit AXIOMS_ISS_URL."""
        config = {
            "AXIOMS_ISS_URL": "https://auth.example.com/oauth2",
            "AXIOMS_DOMAIN": "auth.example.com",
        }

        issuer = get_expected_issuer(config)
        assert issuer == "https://auth.example.com/oauth2"

    def test_from_domain(self):
        """Test constructing issuer from AXIOMS_DOMAIN."""
        config = {"AXIOMS_DOMAIN": "auth.example.com"}

        issuer = get_expected_issuer(config)
        assert issuer == "https://auth.example.com"

    def test_domain_with_https_prefix(self):
        """Test domain with https:// prefix (should be removed)."""
        config = {"AXIOMS_DOMAIN": "https://auth.example.com"}

        issuer = get_expected_issuer(config)
        assert issuer == "https://auth.example.com"

    def test_domain_with_http_prefix(self):
        """Test domain with http:// prefix (should be removed and replaced with https)."""
        config = {"AXIOMS_DOMAIN": "http://auth.example.com"}

        issuer = get_expected_issuer(config)
        assert issuer == "https://auth.example.com"

    def test_no_issuer_config(self):
        """Test when neither AXIOMS_ISS_URL nor AXIOMS_DOMAIN is set."""
        config = {}

        issuer = get_expected_issuer(config)
        assert issuer is None

    def test_none_config(self):
        """Test with None config."""
        issuer = get_expected_issuer(None)
        assert issuer is None

    def test_object_config(self):
        """Test with object config."""

        class Config:
            AXIOMS_ISS_URL = "https://auth.example.com"

        config = Config()
        issuer = get_expected_issuer(config)
        assert issuer == "https://auth.example.com"


class TestGetJWKSUrl:
    """Test get_jwks_url function."""

    def test_explicit_jwks_url(self):
        """Test with explicit AXIOMS_JWKS_URL."""
        config = {
            "AXIOMS_JWKS_URL": "https://auth.example.com/custom/jwks.json",
            "AXIOMS_ISS_URL": "https://auth.example.com",
        }

        jwks_url = get_jwks_url(config)
        assert jwks_url == "https://auth.example.com/custom/jwks.json"

    def test_from_issuer_url(self):
        """Test constructing JWKS URL from AXIOMS_ISS_URL."""
        config = {"AXIOMS_ISS_URL": "https://auth.example.com"}

        jwks_url = get_jwks_url(config)
        assert jwks_url == "https://auth.example.com/.well-known/jwks.json"

    def test_from_domain(self):
        """Test constructing JWKS URL from AXIOMS_DOMAIN."""
        config = {"AXIOMS_DOMAIN": "auth.example.com"}

        jwks_url = get_jwks_url(config)
        assert jwks_url == "https://auth.example.com/.well-known/jwks.json"

    def test_issuer_url_with_path(self):
        """Test JWKS URL construction with issuer URL containing path."""
        config = {"AXIOMS_ISS_URL": "https://auth.example.com/oauth2"}

        jwks_url = get_jwks_url(config)
        assert jwks_url == "https://auth.example.com/oauth2/.well-known/jwks.json"

    def test_no_config(self):
        """Test when no JWKS config is provided."""
        config = {}

        with pytest.raises(Exception) as exc_info:
            get_jwks_url(config)

        assert "Please set either AXIOMS_JWKS_URL" in str(exc_info.value)

    def test_none_config(self):
        """Test with None config."""
        with pytest.raises(Exception) as exc_info:
            get_jwks_url(None)

        assert "Please set either AXIOMS_JWKS_URL" in str(exc_info.value)

    def test_object_config(self):
        """Test with object config."""

        class Config:
            AXIOMS_ISS_URL = "https://auth.example.com"

        config = Config()
        jwks_url = get_jwks_url(config)
        assert jwks_url == "https://auth.example.com/.well-known/jwks.json"

    def test_configuration_hierarchy(self):
        """Test that configuration hierarchy is respected."""
        # 1. AXIOMS_JWKS_URL takes precedence
        config = {
            "AXIOMS_JWKS_URL": "https://custom.com/jwks.json",
            "AXIOMS_ISS_URL": "https://auth.example.com",
            "AXIOMS_DOMAIN": "domain.example.com",
        }
        assert get_jwks_url(config) == "https://custom.com/jwks.json"

        # 2. AXIOMS_ISS_URL is next
        config = {
            "AXIOMS_ISS_URL": "https://auth.example.com",
            "AXIOMS_DOMAIN": "domain.example.com",
        }
        assert get_jwks_url(config) == "https://auth.example.com/.well-known/jwks.json"

        # 3. AXIOMS_DOMAIN is last
        config = {"AXIOMS_DOMAIN": "auth.example.com"}
        assert get_jwks_url(config) == "https://auth.example.com/.well-known/jwks.json"
