"""JWKS (JSON Web Key Set) manager for Axioms authentication.

This module provides both sync and async JWKS managers:
- JWKSManager: Thread-based manager for Flask, Django (WSGI), and other sync frameworks
- AsyncJWKSManager: Asyncio-based manager for FastAPI, Django (ASGI), and other async frameworks
"""

import asyncio
import atexit
import logging
import threading
import time
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

import httpx

from .errors import AxiomsError

if TYPE_CHECKING:
    from .config import AxiomsConfig

logger = logging.getLogger(__name__)


class JWKSManager:
    """Thread-safe JWKS manager with background refresh support.

    This manager handles JWKS fetching with:
    - HTTP requests using httpx (sync mode for framework compatibility)
    - Periodic background refresh using threading
    - In-memory caching with TTL
    - Thread-safe access
    - Framework-agnostic (works with FastAPI, Django, Flask)

    The manager can be initialized on application startup or will lazy-initialize
    on first use with a blocking fetch followed by background refreshes.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern to ensure only one manager instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the JWKS manager."""
        if self._initialized:
            return

        self._jwks_cache = {}  # url -> (data, timestamp)
        self._cache_lock = threading.RLock()
        self._client = None
        self._refresh_thread = None
        self._refresh_interval = 3600  # 1 hour default
        self._cache_ttl = (
            7200  # 2 hours default (matches AxiomsConfig and AsyncJWKSManager)
        )
        self._running = False
        self._stop_event = threading.Event()
        self._initialized = True

        # Register cleanup on exit
        atexit.register(self.shutdown)

    def initialize(
        self,
        jwks_url: str,
        refresh_interval: int = 3600,
        cache_ttl: int = 600,
        prefetch: bool = True,
    ):
        """Initialize the manager and start background refresh.

        Args:
            jwks_url: JWKS URL to fetch.
            refresh_interval: Interval in seconds between refresh attempts (default: 3600).
            cache_ttl: Cache TTL in seconds (default: 600).
            prefetch: If True, pre-fetch JWKS before starting background refresh.
        """
        with self._lock:
            if self._running:
                logger.debug("JWKS manager already running")
                return

            self._refresh_interval = refresh_interval
            self._cache_ttl = cache_ttl

            # Create httpx sync client with timeout
            self._client = httpx.Client(
                timeout=httpx.Timeout(10.0),
                follow_redirects=True,
                verify=True,  # SSL verification enabled
            )

            # Pre-fetch JWKS if requested
            if prefetch:
                try:
                    self._fetch_jwks(jwks_url)
                    logger.info(f"Successfully pre-fetched JWKS from {jwks_url}")
                except Exception as e:
                    logger.warning(f"Failed to pre-fetch JWKS: {e}")
                    # Don't raise - allow fallback to on-demand fetch

            # Start background refresh thread
            self._running = True
            self._stop_event.clear()
            self._refresh_thread = threading.Thread(
                target=self._refresh_loop,
                args=(jwks_url,),
                daemon=True,
                name="JWKSRefreshThread",
            )
            self._refresh_thread.start()
            logger.info(
                f"Started JWKS background refresh (interval: {refresh_interval}s)"
            )

    def shutdown(self):
        """Shutdown the manager and cleanup resources."""
        with self._lock:
            if not self._running:
                return

            self._running = False
            self._stop_event.set()

            # Wait for refresh thread to finish
            if self._refresh_thread and self._refresh_thread.is_alive():
                self._refresh_thread.join(timeout=5.0)

            # Close httpx client
            if self._client:
                self._client.close()
                self._client = None

            logger.info("JWKS manager shutdown complete")

    def _refresh_loop(self, jwks_url: str):
        """Background thread to periodically refresh JWKS.

        Args:
            jwks_url: JWKS URL to refresh.
        """
        while self._running:
            # Wait for refresh interval or stop event
            if self._stop_event.wait(timeout=self._refresh_interval):
                # Stop event was set
                break

            if not self._running:
                break

            try:
                self._fetch_jwks(jwks_url)
                logger.debug(f"Refreshed JWKS from {jwks_url}")
            except Exception as e:
                logger.error(f"Error refreshing JWKS: {e}")

    def _fetch_jwks(self, url: str) -> bytes:
        """Fetch JWKS data from URL using httpx.

        Args:
            url: JWKS URL to fetch.

        Returns:
            bytes: JWKS data.

        Raises:
            AxiomsError: If URL scheme is invalid.
            Exception: If fetch fails.
        """
        # Validate URL scheme
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ("http", "https"):
            logger.error(f"Invalid URL scheme: {parsed_url.scheme}. URL: {url}")
            raise AxiomsError(
                {
                    "error": "server_error",
                    "error_description": (
                        "Invalid JWKS URL configuration. "
                        "Only http and https schemes are allowed."
                    ),
                },
                500,
            )

        # Use httpx client if initialized, otherwise create temporary one
        if self._client is not None:
            response = self._client.get(url)
        else:
            with httpx.Client(
                timeout=httpx.Timeout(10.0), follow_redirects=True, verify=True
            ) as client:
                response = client.get(url)

        response.raise_for_status()
        data = response.content

        # Update cache with thread safety
        with self._cache_lock:
            timestamp = time.time()
            self._jwks_cache[url] = (data, timestamp)

        return data

    def get_jwks(self, url: str) -> bytes:
        """Get JWKS data from cache or fetch if needed.

        This method is thread-safe and can be called from any context.

        Args:
            url: JWKS URL.

        Returns:
            bytes: JWKS data.
        """
        # Check cache first
        with self._cache_lock:
            if url in self._jwks_cache:
                data, timestamp = self._jwks_cache[url]
                age = time.time() - timestamp
                if age < self._cache_ttl:
                    logger.debug(f"JWKS cache hit for {url} (age: {age:.1f}s)")
                    return data

        # Cache miss or expired - fetch new data
        logger.debug(f"JWKS cache miss for {url}, fetching...")
        return self._fetch_jwks(url)


class AsyncJWKSManager:
    """Async JWKS manager with background refresh support for async applications.

    This manager handles JWKS fetching with:
    - HTTP requests using httpx.AsyncClient
    - Periodic background refresh using asyncio
    - In-memory caching with TTL
    - Async-safe access
    - For FastAPI, Django (ASGI), and other async frameworks

    The manager should be initialized on application startup.
    """

    _instance = None
    _lock = asyncio.Lock()

    def __new__(cls):
        """Singleton pattern to ensure only one manager instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the async JWKS manager."""
        if self._initialized:
            return

        self._jwks_cache = {}  # url -> (data, timestamp)
        self._cache_lock = asyncio.Lock()
        self._client = None
        self._refresh_task = None
        self._refresh_interval = 3600  # 1 hour default
        self._cache_ttl = 7200  # 2 hours default
        self._running = False
        self._stop_event = asyncio.Event()
        self._initialized = True

    async def initialize(
        self,
        jwks_url: str,
        refresh_interval: int = 3600,
        cache_ttl: int = 7200,
        prefetch: bool = True,
    ):
        """Initialize the manager and start background refresh.

        Args:
            jwks_url: JWKS URL to fetch.
            refresh_interval: Interval in seconds between refresh attempts (default: 3600).
            cache_ttl: Cache TTL in seconds (default: 7200).
            prefetch: If True, pre-fetch JWKS before starting background refresh.
        """
        if self._running:
            logger.debug("Async JWKS manager already running")
            return

        self._refresh_interval = refresh_interval
        self._cache_ttl = cache_ttl

        # Create httpx async client with timeout
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=True,
            verify=True,  # SSL verification enabled
        )

        # Pre-fetch JWKS if requested
        if prefetch:
            try:
                await self._fetch_jwks(jwks_url)
                logger.info(f"Successfully pre-fetched JWKS from {jwks_url}")
            except Exception as e:
                logger.warning(f"Failed to pre-fetch JWKS: {e}")
                # Don't raise - allow fallback to on-demand fetch

        # Start background refresh task
        self._running = True
        self._stop_event.clear()
        self._refresh_task = asyncio.create_task(self._refresh_loop(jwks_url))
        logger.info(
            f"Started async JWKS background refresh (interval: {refresh_interval}s)"
        )

    async def shutdown(self):
        """Shutdown the manager and cleanup resources."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        # Cancel refresh task
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass

        # Close httpx client
        if self._client:
            await self._client.aclose()
            self._client = None

        logger.info("Async JWKS manager shutdown complete")

    async def _refresh_loop(self, jwks_url: str):
        """Background task to periodically refresh JWKS.

        Args:
            jwks_url: JWKS URL to refresh.
        """
        while self._running:
            try:
                # Wait for refresh interval or stop event
                await asyncio.wait_for(
                    self._stop_event.wait(), timeout=self._refresh_interval
                )
                # Stop event was set
                break
            except asyncio.TimeoutError:
                # Timeout reached, time to refresh
                pass

            if not self._running:
                break

            try:
                await self._fetch_jwks(jwks_url)
                logger.debug(f"Refreshed JWKS from {jwks_url}")
            except Exception as e:
                logger.error(f"Error refreshing JWKS: {e}")

    async def _fetch_jwks(self, url: str) -> bytes:
        """Fetch JWKS data from URL using httpx.

        Args:
            url: JWKS URL to fetch.

        Returns:
            bytes: JWKS data.

        Raises:
            AxiomsError: If URL scheme is invalid.
            Exception: If fetch fails.
        """
        # Validate URL scheme
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ("http", "https"):
            logger.error(f"Invalid URL scheme: {parsed_url.scheme}. URL: {url}")
            raise AxiomsError(
                {
                    "error": "server_error",
                    "error_description": (
                        "Invalid JWKS URL configuration. "
                        "Only http and https schemes are allowed."
                    ),
                },
                500,
            )

        # Use httpx async client if initialized, otherwise create temporary one
        if self._client is not None:
            response = await self._client.get(url)
        else:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0), follow_redirects=True, verify=True
            ) as client:
                response = await client.get(url)

        response.raise_for_status()
        data = response.content

        # Update cache with async safety
        async with self._cache_lock:
            timestamp = time.time()
            self._jwks_cache[url] = (data, timestamp)

        return data

    async def get_jwks(self, url: str) -> bytes:
        """Get JWKS data from cache or fetch if needed.

        This method is async-safe and can be called from async contexts.

        Args:
            url: JWKS URL.

        Returns:
            bytes: JWKS data.
        """
        # Check cache first
        async with self._cache_lock:
            if url in self._jwks_cache:
                data, timestamp = self._jwks_cache[url]
                age = time.time() - timestamp
                if age < self._cache_ttl:
                    logger.debug(f"JWKS cache hit for {url} (age: {age:.1f}s)")
                    return data

        # Cache miss or expired - fetch new data
        logger.debug(f"JWKS cache miss for {url}, fetching...")
        return await self._fetch_jwks(url)


# Global JWKS manager instances
_jwks_manager = JWKSManager()
_async_jwks_manager = AsyncJWKSManager()


def initialize_jwks_manager(
    config: Optional["AxiomsConfig"] = None,
    jwks_url: Optional[str] = None,
    refresh_interval: int = 3600,
    cache_ttl: int = 7200,
    prefetch: bool = True,
):
    """Initialize the global JWKS manager for sync/threading-based frameworks.

    This should be called during application startup to enable background JWKS
    refresh and avoid blocking requests. Uses threading for background refresh.

    Use this for:
    - Flask (WSGI mode - the default, even with async route handlers)
    - Django WSGI
    - Any framework using threading/WSGI

    For truly async frameworks using asyncio event loops:
    - FastAPI: Use initialize_async_jwks_manager
    - Django ASGI: Use initialize_async_jwks_manager
    - Flask (ASGI mode with Hypercorn/Uvicorn): Use initialize_async_jwks_manager

    Note: Flask 2.0+ supports async/await in route handlers but still runs on WSGI
    by default (using thread pools). Only use initialize_async_jwks_manager if running
    Flask on an ASGI server like Hypercorn.

    Args:
        config: AxiomsConfig object (recommended). If provided, uses config values by default.
        jwks_url: JWKS URL to fetch. If None and config provided, uses config.AXIOMS_JWKS_URL.
        refresh_interval: Interval in seconds between refresh attempts (default: 3600).
        cache_ttl: Cache TTL in seconds (default: 7200, must be >= 2x refresh_interval).
        prefetch: If True, pre-fetch JWKS before starting background refresh.

    Example:
        Flask-WSGI::

            from axioms_core import AxiomsConfig, initialize_jwks_manager, shutdown_jwks_manager
            from flask import Flask

            app = Flask(__name__)

            config = AxiomsConfig(
                AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json",
                AXIOMS_JWKS_REFRESH_INTERVAL=1800,
                AXIOMS_JWKS_CACHE_TTL=3600,
            )

            @app.before_first_request
            def startup():
                initialize_jwks_manager(config=config)

            # Shutdown automatically called via atexit, or manually:
            @app.teardown_appcontext
            def shutdown(exception=None):
                shutdown_jwks_manager()

    Example:
        Django-WSGI::

            # In apps.py
            from django.apps import AppConfig
            from axioms_core import initialize_jwks_manager

            class MyAppConfig(AppConfig):
                def ready(self):
                    initialize_jwks_manager(
                        jwks_url="https://auth.example.com/.well-known/jwks.json",
                        refresh_interval=1800,
                        cache_ttl=3600
                    )
    """
    # Use config values if provided
    if config is not None:
        jwks_url = jwks_url or config.AXIOMS_JWKS_URL
        refresh_interval = config.AXIOMS_JWKS_REFRESH_INTERVAL
        cache_ttl = config.AXIOMS_JWKS_CACHE_TTL
        prefetch = config.AXIOMS_JWKS_PREFETCH

    if jwks_url is None:
        raise ValueError(
            "jwks_url must be provided either directly or via config.AXIOMS_JWKS_URL"
        )

    _jwks_manager.initialize(jwks_url, refresh_interval, cache_ttl, prefetch)


def shutdown_jwks_manager():
    """Shutdown the global JWKS manager.

    This should be called during application shutdown to cleanup resources.
    It's also automatically called via atexit registration.
    """
    _jwks_manager.shutdown()


async def initialize_async_jwks_manager(
    config: Optional["AxiomsConfig"] = None,
    jwks_url: Optional[str] = None,
    refresh_interval: int = 3600,
    cache_ttl: int = 7200,
    prefetch: bool = True,
):
    """Initialize the global async JWKS manager for asyncio-based frameworks.

    This should be called during application startup to enable background JWKS
    refresh and avoid blocking requests. Uses asyncio for background refresh.

    Use this for frameworks running on asyncio event loops:
    - FastAPI (always uses asyncio)
    - Django ASGI (async mode)
    - Flask on ASGI servers (Hypercorn, Uvicorn, etc.)
    - Any ASGI application

    For threading-based frameworks, use initialize_jwks_manager instead:
    - Flask (WSGI mode - the default)
    - Django WSGI

    Note: Flask 2.0+ supports async/await syntax but runs on WSGI by default.
    Only use this function if running Flask on an ASGI server like Hypercorn.

    Args:
        config: AxiomsConfig object (recommended). If provided, uses config values by default.
        jwks_url: JWKS URL to fetch. If None and config provided, uses config.AXIOMS_JWKS_URL.
        refresh_interval: Interval in seconds between refresh attempts (default: 3600).
        cache_ttl: Cache TTL in seconds (default: 7200, must be >= 2x refresh_interval).
        prefetch: If True, pre-fetch JWKS before starting background refresh.

    Example:
        with FastAPI (lifespan context manager)::

            from contextlib import asynccontextmanager
            from fastapi import FastAPI
            from axioms_core import (
                AxiomsConfig,
                initialize_async_jwks_manager,
                shutdown_async_jwks_manager
            )

            config = AxiomsConfig(
                AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json",
                AXIOMS_JWKS_REFRESH_INTERVAL=1800,
                AXIOMS_JWKS_CACHE_TTL=3600,
            )

            @asynccontextmanager
            async def lifespan(app: FastAPI):
                # Startup
                await initialize_async_jwks_manager(config=config)
                yield
                # Shutdown
                await shutdown_async_jwks_manager()

            app = FastAPI(lifespan=lifespan)

    Example:
        FastAPI with startup/shutdown events::

            from fastapi import FastAPI
            from axioms_core import initialize_async_jwks_manager, shutdown_async_jwks_manager

            app = FastAPI()

            @app.on_event("startup")
            async def startup():
                await initialize_async_jwks_manager(
                    jwks_url="https://auth.example.com/.well-known/jwks.json"
                )

            @app.on_event("shutdown")
            async def shutdown():
                await shutdown_async_jwks_manager()

    Example:
        Django-ASGI::

            # In asgi.py
            from django.core.asgi import get_asgi_application
            from axioms_core import initialize_async_jwks_manager
            import asyncio

            # Initialize JWKS manager before application starts
            asyncio.run(initialize_async_jwks_manager(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                refresh_interval=1800,
                cache_ttl=3600
            ))

            application = get_asgi_application()
    """
    # Use config values if provided
    if config is not None:
        jwks_url = jwks_url or config.AXIOMS_JWKS_URL
        refresh_interval = config.AXIOMS_JWKS_REFRESH_INTERVAL
        cache_ttl = config.AXIOMS_JWKS_CACHE_TTL
        prefetch = config.AXIOMS_JWKS_PREFETCH

    if jwks_url is None:
        raise ValueError(
            "jwks_url must be provided either directly or via config.AXIOMS_JWKS_URL"
        )

    await _async_jwks_manager.initialize(
        jwks_url, refresh_interval, cache_ttl, prefetch
    )


async def shutdown_async_jwks_manager():
    """Shutdown the global async JWKS manager.

    This should be called during application shutdown to cleanup resources.
    """
    await _async_jwks_manager.shutdown()
