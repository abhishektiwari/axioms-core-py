"""Tests for token validation functions."""

import time

import jwt as pyjwt
import pytest
from jwcrypto import jwk

from axioms_core.errors import AxiomsError
from axioms_core.helper import (
    ALLOWED_ALGORITHMS,
    check_token_validity,
    get_key_from_jwks_json,
)


class TestCheckTokenValidity:
    """Test check_token_validity function."""

    def test_valid_token(self, valid_token, rsa_keypair):
        """Test validation of a valid token."""
        header = pyjwt.get_unverified_header(valid_token)
        alg = header["alg"]

        payload = check_token_validity(
            token=valid_token,
            key=rsa_keypair,
            alg=alg,
            audience="test-audience",
            issuer="https://auth.example.com",
        )

        assert payload is not None
        assert payload.sub == "test-user"
        assert payload.aud == "test-audience"
        assert payload.iss == "https://auth.example.com"

    def test_valid_token_without_issuer(self, valid_token, rsa_keypair):
        """Test validation without issuer check."""
        header = pyjwt.get_unverified_header(valid_token)
        alg = header["alg"]

        payload = check_token_validity(
            token=valid_token,
            key=rsa_keypair,
            alg=alg,
            audience="test-audience",
            issuer=None,
        )

        assert payload is not None
        assert payload.sub == "test-user"

    def test_expired_token(self, expired_token, rsa_keypair):
        """Test validation of expired token."""
        header = pyjwt.get_unverified_header(expired_token)
        alg = header["alg"]

        payload = check_token_validity(
            token=expired_token,
            key=rsa_keypair,
            alg=alg,
            audience="test-audience",
            issuer="https://auth.example.com",
        )

        assert payload is None

    def test_wrong_audience(self, token_wrong_audience, rsa_keypair):
        """Test validation with wrong audience."""
        header = pyjwt.get_unverified_header(token_wrong_audience)
        alg = header["alg"]

        payload = check_token_validity(
            token=token_wrong_audience,
            key=rsa_keypair,
            alg=alg,
            audience="test-audience",
            issuer="https://auth.example.com",
        )

        assert payload is None

    def test_wrong_issuer(self, token_wrong_issuer, rsa_keypair):
        """Test validation with wrong issuer."""
        header = pyjwt.get_unverified_header(token_wrong_issuer)
        alg = header["alg"]

        payload = check_token_validity(
            token=token_wrong_issuer,
            key=rsa_keypair,
            alg=alg,
            audience="test-audience",
            issuer="https://auth.example.com",
        )

        assert payload is None

    def test_invalid_signature(self, valid_token, rsa_keypair):
        """Test validation with invalid signature."""
        # Create a different key
        wrong_key = jwk.JWK.generate(kty="RSA", size=2048)

        header = pyjwt.get_unverified_header(valid_token)
        alg = header["alg"]

        payload = check_token_validity(
            token=valid_token,
            key=wrong_key,
            alg=alg,
            audience="test-audience",
            issuer="https://auth.example.com",
        )

        assert payload is None

    def test_malformed_token(self, rsa_keypair):
        """Test validation with malformed token."""
        payload = check_token_validity(
            token="not.a.valid.jwt.token",
            key=rsa_keypair,
            alg="RS256",
            audience="test-audience",
            issuer="https://auth.example.com",
        )

        assert payload is None

    def test_token_missing_exp(self, rsa_keypair):
        """Test validation with token missing exp claim."""
        from jwcrypto import jwt

        now = int(time.time())
        payload_data = {
            "sub": "test-user",
            "aud": "test-audience",
            "iss": "https://auth.example.com",
            "iat": now,
            # Missing exp claim
        }

        token = jwt.JWT(
            header={"alg": "RS256", "kid": "test-key-id"}, claims=payload_data
        )
        token.make_signed_token(rsa_keypair)
        token_str = token.serialize()

        # This should fail because exp is required
        payload = check_token_validity(
            token=token_str,
            key=rsa_keypair,
            alg="RS256",
            audience="test-audience",
            issuer="https://auth.example.com",
        )

        assert payload is None

    def test_frozen_box_immutable(self, valid_token, rsa_keypair):
        """Test that returned payload is immutable (frozen Box)."""
        header = pyjwt.get_unverified_header(valid_token)
        alg = header["alg"]

        payload = check_token_validity(
            token=valid_token,
            key=rsa_keypair,
            alg=alg,
            audience="test-audience",
            issuer="https://auth.example.com",
        )

        # Attempt to modify should raise
        with pytest.raises(Exception):  # Box raises BoxError on modification
            payload.sub = "hacker"


class TestGetKeyFromJWKSJson:
    """Test get_key_from_jwks_json function."""

    def test_get_key_success(self, config_dict, mock_jwks_response, rsa_keypair):
        """Test successful key retrieval from JWKS."""
        from unittest.mock import patch

        with patch("axioms_core.helper._jwks_manager") as mock_manager:
            mock_manager.get_jwks.return_value = mock_jwks_response.content

            key = get_key_from_jwks_json("test-key-id", config_dict)

            assert key is not None
            mock_manager.get_jwks.assert_called_once()

    def test_get_key_not_found(self, config_dict, jwks_data):
        """Test key retrieval when kid not in JWKS."""
        from unittest.mock import patch

        # Create JWKS with a different kid
        from jwcrypto import jwk

        different_key = jwk.JWK.generate(kty="RSA", size=2048, kid="different-key-id")
        keyset = jwk.JWKSet()
        keyset.add(different_key)
        different_jwks = keyset.export(private_keys=False).encode("utf-8")

        with patch("axioms_core.helper._jwks_manager") as mock_manager:
            mock_manager.get_jwks.return_value = different_jwks

            with pytest.raises(AxiomsError) as exc_info:
                get_key_from_jwks_json("non-existent-kid", config_dict)

            assert exc_info.value.status_code == 401
            assert "Invalid access token" in exc_info.value.error["error_description"]

    def test_get_key_invalid_jwks(self, config_dict):
        """Test key retrieval with invalid JWKS data."""
        from unittest.mock import patch

        with patch("axioms_core.helper._jwks_manager") as mock_manager:
            mock_manager.get_jwks.return_value = b"invalid json"

            with pytest.raises(AxiomsError) as exc_info:
                get_key_from_jwks_json("test-key-id", config_dict)

            assert exc_info.value.status_code == 401


class TestAllowedAlgorithms:
    """Test ALLOWED_ALGORITHMS constant."""

    def test_allowed_algorithms_contains_secure_algs(self):
        """Test that ALLOWED_ALGORITHMS contains only secure algorithms."""
        expected = {
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
        }

        assert ALLOWED_ALGORITHMS == expected

    def test_allowed_algorithms_excludes_symmetric(self):
        """Test that ALLOWED_ALGORITHMS excludes symmetric algorithms."""
        # These should NOT be in ALLOWED_ALGORITHMS (prevent algorithm confusion)
        insecure = ["HS256", "HS384", "HS512", "none"]

        for alg in insecure:
            assert alg not in ALLOWED_ALGORITHMS

    def test_allowed_algorithms_frozen(self):
        """Test that ALLOWED_ALGORITHMS is immutable."""
        # frozenset should not allow modifications
        with pytest.raises(AttributeError):
            ALLOWED_ALGORITHMS.add("HS256")
