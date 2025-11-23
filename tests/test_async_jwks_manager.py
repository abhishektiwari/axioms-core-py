"""Tests for AsyncJWKSManager."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from axioms_core.errors import AxiomsError
from axioms_core.jwks import AsyncJWKSManager, _async_jwks_manager


class TestAsyncJWKSManager:
    """Test AsyncJWKSManager functionality."""

    @pytest.mark.asyncio
    async def test_singleton_pattern(self):
        """Test that AsyncJWKSManager follows singleton pattern."""
        manager1 = AsyncJWKSManager()
        manager2 = AsyncJWKSManager()
        assert manager1 is manager2

    @pytest.mark.asyncio
    async def test_initialize_without_prefetch(self, config_dict, mock_jwks_response):
        """Test initialization without prefetch."""
        manager = AsyncJWKSManager()

        # Ensure clean state
        await manager.shutdown()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            await manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=10,
                cache_ttl=20,
                prefetch=False,
            )

            assert manager._running is True
            assert manager._refresh_interval == 10
            assert manager._cache_ttl == 20
            assert manager._refresh_task is not None
            assert not manager._refresh_task.done()

            # Cleanup
            await manager.shutdown()

    @pytest.mark.asyncio
    async def test_initialize_with_prefetch(self, config_dict, mock_jwks_response):
        """Test initialization with prefetch."""
        manager = AsyncJWKSManager()

        # Ensure clean state
        await manager.shutdown()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_jwks_response)
            mock_client_class.return_value = mock_client

            await manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=10,
                cache_ttl=20,
                prefetch=True,
            )

            # Verify prefetch happened
            mock_client.get.assert_called_once()
            assert (
                "https://auth.example.com/.well-known/jwks.json" in manager._jwks_cache
            )

            # Cleanup
            await manager.shutdown()

    @pytest.mark.asyncio
    async def test_fetch_jwks_success(self, mock_jwks_response):
        """Test successful JWKS fetch."""
        manager = AsyncJWKSManager()
        await manager.shutdown()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_jwks_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            url = "https://auth.example.com/.well-known/jwks.json"
            data = await manager._fetch_jwks(url)

            assert data == mock_jwks_response.content
            assert url in manager._jwks_cache

    @pytest.mark.asyncio
    async def test_fetch_jwks_invalid_scheme(self):
        """Test JWKS fetch with invalid URL scheme."""
        manager = AsyncJWKSManager()

        with pytest.raises(AxiomsError) as exc_info:
            await manager._fetch_jwks("file:///etc/passwd")

        assert exc_info.value.status_code == 500
        assert (
            "Invalid JWKS URL configuration"
            in exc_info.value.error["error_description"]
        )

    @pytest.mark.asyncio
    async def test_fetch_jwks_http_error(self):
        """Test JWKS fetch with HTTP error."""
        manager = AsyncJWKSManager()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "404 Not Found", request=MagicMock(), response=MagicMock()
            )
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            with pytest.raises(httpx.HTTPStatusError):
                await manager._fetch_jwks(
                    "https://auth.example.com/.well-known/jwks.json"
                )

    @pytest.mark.asyncio
    async def test_get_jwks_from_cache(self, mock_jwks_response):
        """Test getting JWKS from cache."""
        import time

        manager = AsyncJWKSManager()
        await manager.shutdown()

        url = "https://auth.example.com/.well-known/jwks.json"

        # Populate cache
        async with manager._cache_lock:
            manager._jwks_cache[url] = (mock_jwks_response.content, time.time())

        # Get from cache (should not make HTTP request)
        with patch("httpx.AsyncClient") as mock_client_class:
            data = await manager.get_jwks(url)

            # Should not have created a client
            mock_client_class.assert_not_called()
            assert data == mock_jwks_response.content

    @pytest.mark.asyncio
    async def test_get_jwks_cache_expired(self, mock_jwks_response):
        """Test getting JWKS when cache is expired."""
        import time

        manager = AsyncJWKSManager()
        await manager.shutdown()
        manager._cache_ttl = 1

        url = "https://auth.example.com/.well-known/jwks.json"

        # Populate cache with expired entry
        async with manager._cache_lock:
            manager._jwks_cache[url] = (b"old-data", time.time() - 10)

        # Get from URL (cache expired)
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_jwks_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            data = await manager.get_jwks(url)

            # Should have fetched new data
            mock_client.get.assert_called_once()
            assert data == mock_jwks_response.content

    @pytest.mark.asyncio
    async def test_background_refresh(self, mock_jwks_response):
        """Test background refresh task."""
        manager = AsyncJWKSManager()
        await manager.shutdown()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_jwks_response)
            mock_client_class.return_value = mock_client

            # Initialize with short refresh interval
            await manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=1,  # 1 second
                cache_ttl=10,
                prefetch=True,
            )

            # Wait for at least one refresh cycle (prefetch + 1 refresh + buffer)
            await asyncio.sleep(2.5)

            # Should have made multiple calls (prefetch + at least one refresh)
            assert mock_client.get.call_count >= 2

            # Cleanup
            await manager.shutdown()

    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test manager shutdown."""
        manager = AsyncJWKSManager()
        await manager.shutdown()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client

            await manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=10,
                cache_ttl=20,
                prefetch=False,
            )

            assert manager._running is True

            await manager.shutdown()

            assert manager._running is False
            assert manager._client is None

            # Task should be cancelled
            await asyncio.sleep(0.1)
            if manager._refresh_task:
                assert manager._refresh_task.done()

    @pytest.mark.asyncio
    async def test_shutdown_idempotent(self):
        """Test that shutdown can be called multiple times safely."""
        manager = AsyncJWKSManager()

        await manager.shutdown()
        await manager.shutdown()  # Should not raise

    @pytest.mark.asyncio
    async def test_initialize_idempotent(self, mock_jwks_response):
        """Test that initialize can be called multiple times safely."""
        manager = AsyncJWKSManager()
        await manager.shutdown()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_jwks_response)
            mock_client_class.return_value = mock_client

            await manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=10,
                cache_ttl=20,
                prefetch=False,
            )

            # Call again - should return early
            await manager.initialize(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=20,
                cache_ttl=40,
                prefetch=False,
            )

            # Interval should still be 10 (first call)
            assert manager._refresh_interval == 10

            await manager.shutdown()


@pytest.mark.asyncio
async def test_initialize_async_jwks_manager(mock_jwks_response):
    """Test global initialize_async_jwks_manager function."""
    from axioms_core import initialize_async_jwks_manager, shutdown_async_jwks_manager

    await shutdown_async_jwks_manager()

    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_jwks_response)
        mock_client_class.return_value = mock_client

        await initialize_async_jwks_manager(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
            refresh_interval=10,
            cache_ttl=20,
            prefetch=True,
        )

        assert _async_jwks_manager._running is True

        await shutdown_async_jwks_manager()
        assert _async_jwks_manager._running is False


@pytest.mark.asyncio
async def test_shutdown_async_jwks_manager():
    """Test global shutdown_async_jwks_manager function."""
    from axioms_core import shutdown_async_jwks_manager

    # Should not raise even if not initialized
    await shutdown_async_jwks_manager()
