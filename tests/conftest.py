"""Pytest fixtures for axioms-core tests."""

import time

import pytest
from jwcrypto import jwk, jwt


@pytest.fixture
def rsa_keypair():
    """Generate RSA key pair for testing."""
    key = jwk.JWK.generate(kty="RSA", size=2048, kid="test-key-id")
    return key


@pytest.fixture
def jwks_data(rsa_keypair):
    """Generate JWKS data for testing."""
    keyset = jwk.JWKSet()
    keyset.add(rsa_keypair)
    return keyset.export(private_keys=False).encode("utf-8")


@pytest.fixture
def valid_token(rsa_keypair):
    """Generate a valid JWT token."""
    now = int(time.time())
    payload = {
        "sub": "test-user",
        "aud": "test-audience",
        "iss": "https://auth.example.com",
        "exp": now + 3600,
        "iat": now,
        "scope": "read:data write:data",
        "roles": ["admin", "editor"],
        "permissions": ["users:read", "users:write"],
    }

    token = jwt.JWT(header={"alg": "RS256", "kid": "test-key-id"}, claims=payload)
    token.make_signed_token(rsa_keypair)
    return token.serialize()


@pytest.fixture
def expired_token(rsa_keypair):
    """Generate an expired JWT token."""
    now = int(time.time())
    payload = {
        "sub": "test-user",
        "aud": "test-audience",
        "iss": "https://auth.example.com",
        "exp": now - 3600,  # Expired 1 hour ago
        "iat": now - 7200,
    }

    token = jwt.JWT(header={"alg": "RS256", "kid": "test-key-id"}, claims=payload)
    token.make_signed_token(rsa_keypair)
    return token.serialize()


@pytest.fixture
def token_wrong_audience(rsa_keypair):
    """Generate a token with wrong audience."""
    now = int(time.time())
    payload = {
        "sub": "test-user",
        "aud": "wrong-audience",
        "iss": "https://auth.example.com",
        "exp": now + 3600,
        "iat": now,
    }

    token = jwt.JWT(header={"alg": "RS256", "kid": "test-key-id"}, claims=payload)
    token.make_signed_token(rsa_keypair)
    return token.serialize()


@pytest.fixture
def token_wrong_issuer(rsa_keypair):
    """Generate a token with wrong issuer."""
    now = int(time.time())
    payload = {
        "sub": "test-user",
        "aud": "test-audience",
        "iss": "https://wrong-issuer.com",
        "exp": now + 3600,
        "iat": now,
    }

    token = jwt.JWT(header={"alg": "RS256", "kid": "test-key-id"}, claims=payload)
    token.make_signed_token(rsa_keypair)
    return token.serialize()


@pytest.fixture
def config_dict():
    """Sample configuration dictionary."""
    return {
        "AXIOMS_JWKS_URL": "https://auth.example.com/.well-known/jwks.json",
        "AXIOMS_ISS_URL": "https://auth.example.com",
        "AXIOMS_AUDIENCE": "test-audience",
        "AXIOMS_DOMAIN": "auth.example.com",
    }


@pytest.fixture
def config_object():
    """Sample configuration object."""

    class Config:
        AXIOMS_JWKS_URL = "https://auth.example.com/.well-known/jwks.json"
        AXIOMS_ISS_URL = "https://auth.example.com"
        AXIOMS_AUDIENCE = "test-audience"
        AXIOMS_DOMAIN = "auth.example.com"

    return Config()


@pytest.fixture
def mock_jwks_response(jwks_data):
    """Mock JWKS HTTP response."""

    class MockResponse:
        def __init__(self):
            self.content = jwks_data
            self.status_code = 200

        def raise_for_status(self):
            pass

    return MockResponse()
