"""Tests for JWKSManager."""

import threading
import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from axioms_core.errors import AxiomsError
from axioms_core.jwks import JWKSManager, _jwks_manager


class TestJWKSManager:
    """Test JWKSManager functionality."""

    def test_singleton_pattern(self):
        """Test that JWKSManager follows singleton pattern."""
        manager1 = JWKSManager()
        manager2 = JWKSManager()
        assert manager1 is manager2

    def test_initialize_without_prefetch(self, config_dict, mock_jwks_response):
        """Test initialization without prefetch."""
        manager = JWKSManager()

        # Ensure clean state
        manager.shutdown()

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=10,
                cache_ttl=5,
                prefetch=False,
            )

            assert manager._running is True
            assert manager._refresh_interval == 10
            assert manager._cache_ttl == 5
            assert manager._refresh_thread is not None
            assert manager._refresh_thread.is_alive()

            # Cleanup
            manager.shutdown()

    def test_initialize_with_prefetch(self, config_dict, mock_jwks_response):
        """Test initialization with prefetch."""
        manager = JWKSManager()

        # Ensure clean state
        manager.shutdown()

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_jwks_response
            mock_client_class.return_value = mock_client

            manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=10,
                cache_ttl=5,
                prefetch=True,
            )

            # Verify prefetch happened
            mock_client.get.assert_called_once()
            assert (
                "https://auth.example.com/.well-known/jwks.json" in manager._jwks_cache
            )

            # Cleanup
            manager.shutdown()

    def test_fetch_jwks_success(self, mock_jwks_response):
        """Test successful JWKS fetch."""
        manager = JWKSManager()
        manager.shutdown()

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_jwks_response
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = False
            mock_client_class.return_value = mock_client

            url = "https://auth.example.com/.well-known/jwks.json"
            data = manager._fetch_jwks(url)

            assert data == mock_jwks_response.content
            assert url in manager._jwks_cache

    def test_fetch_jwks_invalid_scheme(self):
        """Test JWKS fetch with invalid URL scheme."""
        manager = JWKSManager()

        with pytest.raises(AxiomsError) as exc_info:
            manager._fetch_jwks("file:///etc/passwd")

        assert exc_info.value.status_code == 500
        assert (
            "Invalid JWKS URL configuration"
            in exc_info.value.error["error_description"]
        )

    def test_fetch_jwks_http_error(self):
        """Test JWKS fetch with HTTP error."""
        manager = JWKSManager()

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "404 Not Found", request=MagicMock(), response=MagicMock()
            )
            mock_client.get.return_value = mock_response
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = False
            mock_client_class.return_value = mock_client

            with pytest.raises(httpx.HTTPStatusError):
                manager._fetch_jwks("https://auth.example.com/.well-known/jwks.json")

    def test_get_jwks_from_cache(self, mock_jwks_response):
        """Test getting JWKS from cache."""
        manager = JWKSManager()
        manager.shutdown()

        url = "https://auth.example.com/.well-known/jwks.json"

        # Populate cache
        with manager._cache_lock:
            manager._jwks_cache[url] = (mock_jwks_response.content, time.time())

        # Get from cache (should not make HTTP request)
        with patch("httpx.Client") as mock_client_class:
            data = manager.get_jwks(url)

            # Should not have created a client
            mock_client_class.assert_not_called()
            assert data == mock_jwks_response.content

    def test_get_jwks_cache_expired(self, mock_jwks_response):
        """Test getting JWKS when cache is expired."""
        manager = JWKSManager()
        manager.shutdown()
        manager._cache_ttl = 1

        url = "https://auth.example.com/.well-known/jwks.json"

        # Populate cache with expired entry
        with manager._cache_lock:
            manager._jwks_cache[url] = (b"old-data", time.time() - 10)

        # Get from URL (cache expired)
        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_jwks_response
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = False
            mock_client_class.return_value = mock_client

            data = manager.get_jwks(url)

            # Should have fetched new data
            mock_client.get.assert_called_once()
            assert data == mock_jwks_response.content

    def test_background_refresh(self, mock_jwks_response):
        """Test background refresh thread."""
        manager = JWKSManager()
        manager.shutdown()

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_jwks_response
            mock_client_class.return_value = mock_client

            # Initialize with short refresh interval
            manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=1,  # 1 second
                cache_ttl=10,
                prefetch=True,
            )

            # Wait for at least one refresh cycle
            time.sleep(2)

            # Should have made multiple calls (prefetch + at least one refresh)
            assert mock_client.get.call_count >= 2

            # Cleanup
            manager.shutdown()

    def test_shutdown(self):
        """Test manager shutdown."""
        manager = JWKSManager()
        manager.shutdown()

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=10,
                cache_ttl=5,
                prefetch=False,
            )

            assert manager._running is True

            manager.shutdown()

            assert manager._running is False
            assert manager._client is None

            # Thread should be stopped
            time.sleep(0.5)
            if manager._refresh_thread:
                assert not manager._refresh_thread.is_alive()

    def test_shutdown_idempotent(self):
        """Test that shutdown can be called multiple times safely."""
        manager = JWKSManager()

        manager.shutdown()
        manager.shutdown()  # Should not raise

    def test_initialize_idempotent(self, mock_jwks_response):
        """Test that initialize can be called multiple times safely."""
        manager = JWKSManager()
        manager.shutdown()

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_jwks_response
            mock_client_class.return_value = mock_client

            manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=10,
                prefetch=False,
            )

            # Call again - should return early
            manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=20,
                prefetch=False,
            )

            # Interval should still be 10 (first call)
            assert manager._refresh_interval == 10

            manager.shutdown()

    def test_thread_safety(self, mock_jwks_response):
        """Test thread-safe access to cache."""
        manager = JWKSManager()
        manager.shutdown()

        url = "https://auth.example.com/.well-known/jwks.json"

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_jwks_response
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = False
            mock_client_class.return_value = mock_client

            # Fetch from multiple threads
            errors = []

            def fetch():
                try:
                    manager.get_jwks(url)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=fetch) for _ in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # No errors should occur
            assert len(errors) == 0


def test_initialize_jwks_manager(mock_jwks_response):
    """Test global initialize_jwks_manager function."""
    from axioms_core import initialize_jwks_manager, shutdown_jwks_manager

    shutdown_jwks_manager()

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.get.return_value = mock_jwks_response
        mock_client_class.return_value = mock_client

        initialize_jwks_manager(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
            refresh_interval=10,
            cache_ttl=5,
            prefetch=True,
        )

        assert _jwks_manager._running is True

        shutdown_jwks_manager()
        assert _jwks_manager._running is False


def test_shutdown_jwks_manager():
    """Test global shutdown_jwks_manager function."""
    from axioms_core import shutdown_jwks_manager

    # Should not raise even if not initialized
    shutdown_jwks_manager()
