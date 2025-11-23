"""Integration tests for end-to-end flows."""

import time
from unittest.mock import MagicMock, patch

import jwt as pyjwt

from axioms_core import (
    check_permissions,
    check_roles,
    check_scopes,
    check_token_validity,
    get_key_from_jwks_json,
    initialize_jwks_manager,
    shutdown_jwks_manager,
)


class TestEndToEndFlow:
    """Test complete end-to-end authentication flow."""

    def test_complete_auth_flow(
        self, valid_token, rsa_keypair, config_dict, mock_jwks_response
    ):
        """Test complete authentication and authorization flow."""
        # Setup
        shutdown_jwks_manager()

        with patch("axioms_core.helper._jwks_manager") as mock_manager:
            mock_manager.get_jwks.return_value = mock_jwks_response.content

            # 1. Get token header
            header = pyjwt.get_unverified_header(valid_token)
            kid = header.get("kid")
            alg = header.get("alg")

            # 2. Get public key from JWKS
            key = get_key_from_jwks_json(kid, config_dict)

            # 3. Validate token
            payload = check_token_validity(
                token=valid_token,
                key=key,
                alg=alg,
                audience="test-audience",
                issuer="https://auth.example.com",
            )

            assert payload is not None
            assert payload.sub == "test-user"

            # 4. Check scopes
            scopes = payload.scope
            assert check_scopes(scopes, ["read:data"]) is True
            assert check_scopes(scopes, ["admin"]) is False

            # 5. Check roles
            roles = payload.roles
            assert check_roles(roles, ["admin"]) is True
            assert check_roles(roles, ["superuser"]) is False

            # 6. Check permissions
            permissions = payload.permissions
            assert check_permissions(permissions, ["users:read"]) is True
            assert check_permissions(permissions, ["users:delete"]) is False

    def test_with_jwks_manager(
        self, valid_token, rsa_keypair, config_dict, mock_jwks_response
    ):
        """Test flow with initialized JWKS manager."""
        shutdown_jwks_manager()

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_jwks_response
            mock_client_class.return_value = mock_client

            # Initialize manager
            initialize_jwks_manager(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=10,
                cache_ttl=5,
                prefetch=True,
            )

            # Get token header
            header = pyjwt.get_unverified_header(valid_token)
            kid = header.get("kid")
            alg = header.get("alg")

            # Get key (should use cached JWKS)
            key = get_key_from_jwks_json(kid, config_dict)

            # Validate token
            payload = check_token_validity(
                token=valid_token,
                key=key,
                alg=alg,
                audience="test-audience",
                issuer="https://auth.example.com",
            )

            assert payload is not None
            assert payload.sub == "test-user"

            # Cleanup
            shutdown_jwks_manager()

    def test_invalid_token_flow(
        self, expired_token, rsa_keypair, config_dict, mock_jwks_response
    ):
        """Test flow with invalid (expired) token."""
        with patch("axioms_core.helper._jwks_manager") as mock_manager:
            mock_manager.get_jwks.return_value = mock_jwks_response.content

            # Get token header
            header = pyjwt.get_unverified_header(expired_token)
            kid = header.get("kid")
            alg = header.get("alg")

            # Get public key from JWKS
            key = get_key_from_jwks_json(kid, config_dict)

            # Validate token (should fail)
            payload = check_token_validity(
                token=expired_token,
                key=key,
                alg=alg,
                audience="test-audience",
                issuer="https://auth.example.com",
            )

            assert payload is None

    def test_authorization_failure_flow(
        self, valid_token, rsa_keypair, config_dict, mock_jwks_response
    ):
        """Test flow with authorization failures."""
        with patch("axioms_core.helper._jwks_manager") as mock_manager:
            mock_manager.get_jwks.return_value = mock_jwks_response.content

            # Get token header and validate
            header = pyjwt.get_unverified_header(valid_token)
            key = get_key_from_jwks_json(header.get("kid"), config_dict)
            payload = check_token_validity(
                valid_token,
                key,
                header.get("alg"),
                "test-audience",
                "https://auth.example.com",
            )

            assert payload is not None

            # User has "admin" and "editor" roles but not "superuser"
            assert check_roles(payload.roles, ["superuser"]) is False

            # User has "users:read" and "users:write" but not "users:delete"
            assert check_permissions(payload.permissions, ["users:delete"]) is False

            # User has "read:data" and "write:data" scopes but not "admin"
            assert check_scopes(payload.scope, ["admin"]) is False


class TestJWKSManagerIntegration:
    """Test JWKS manager in realistic scenarios."""

    def test_key_rotation_simulation(self, mock_jwks_response):
        """Test simulated key rotation scenario."""
        shutdown_jwks_manager()

        call_count = [0]
        responses = []

        def get_side_effect(url):
            call_count[0] += 1
            # Simulate different JWKS after rotation
            if call_count[0] == 1:
                responses.append("initial")
                return mock_jwks_response
            else:
                responses.append("rotated")
                return mock_jwks_response

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get.side_effect = get_side_effect
            mock_client_class.return_value = mock_client

            # Initialize with short refresh interval
            initialize_jwks_manager(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=1,  # 1 second
                cache_ttl=10,
                prefetch=True,
            )

            # Wait for at least one refresh
            time.sleep(2)

            # Should have multiple fetches (prefetch + refresh)
            assert call_count[0] >= 2

            shutdown_jwks_manager()

    def test_concurrent_requests(
        self, valid_token, rsa_keypair, config_dict, mock_jwks_response
    ):
        """Test concurrent token validation requests."""
        import threading

        shutdown_jwks_manager()

        with patch("axioms_core.helper._jwks_manager") as mock_manager:
            mock_manager.get_jwks.return_value = mock_jwks_response.content

            results = []
            errors = []

            def validate():
                try:
                    header = pyjwt.get_unverified_header(valid_token)
                    key = get_key_from_jwks_json(header.get("kid"), config_dict)
                    payload = check_token_validity(
                        valid_token,
                        key,
                        header.get("alg"),
                        "test-audience",
                        "https://auth.example.com",
                    )
                    results.append(payload is not None)
                except Exception as e:
                    errors.append(e)

            # Run 10 concurrent validations
            threads = [threading.Thread(target=validate) for _ in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # All should succeed
            assert len(errors) == 0
            assert all(results)
            assert len(results) == 10
