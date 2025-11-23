# Axioms Core

Core JWT authentication and authorization logic shared by Axioms packages for FastAPI, Django, and Flask.

## Overview

`axioms-core-py` provides framework-agnostic JWT token validation, JWKS key retrieval with background refresh, and claim-based authorization. This package is used by:

- `axioms-fastapi` - FastAPI integration
- `axioms-drf-py` - Django REST Framework integration
- `axioms-flask-py` - Flask integration

## Features

- **Framework-agnostic JWT validation** - Works with any Python web framework
- **Async JWKS fetching with background refresh** - Non-blocking JWKS retrieval using httpx with periodic background updates
- **Thread-safe caching** - In-memory JWKS cache with configurable TTL
- **Secure by default** - Only allows asymmetric algorithms (RS256, ES256, PS256, etc.)
- **Configurable** - Support for custom claim names for scopes, roles, and permissions
- **Production-ready** - Comprehensive error handling and logging

## Installation

```bash
pip install axioms-core-py
```

## Quick Start

### Initialize JWKS Manager (Recommended)

Initialize the JWKS manager at application startup to enable background refresh:

```python
from axioms_core import initialize_jwks_manager, shutdown_jwks_manager

# At startup
config = {
    "AXIOMS_JWKS_URL": "https://auth.example.com/.well-known/jwks.json",
    "AXIOMS_AUDIENCE": "your-api-audience",
}

initialize_jwks_manager(
    config=config,
    refresh_interval=1800,  # Refresh every 30 minutes
    cache_ttl=600,          # Cache for 10 minutes
    prefetch=True           # Fetch JWKS immediately
)

# At shutdown
shutdown_jwks_manager()
```

### Token Validation

```python
from axioms_core import get_key_from_jwks_json, check_token_validity
import jwt

# Get token header
header = jwt.get_unverified_header(token)
kid = header.get("kid")
alg = header.get("alg")

# Get public key from JWKS (uses cache)
key = get_key_from_jwks_json(kid, config)

# Validate token
payload = check_token_validity(
    token=token,
    key=key,
    alg=alg,
    audience="your-api-audience",
    issuer="https://auth.example.com"
)

if payload:
    print(f"Token valid for user: {payload.sub}")
else:
    print("Token validation failed")
```

### Authorization Checks

```python
from axioms_core import check_scopes, check_roles, check_permissions

# Check scopes (space-separated string)
has_scope = check_scopes("read:data write:data", ["read:data"])

# Check roles (list)
has_role = check_roles(["admin", "editor"], ["admin"])

# Check permissions (list)
has_permission = check_permissions(["users:read", "users:write"], ["users:read"])
```

## Configuration

The core package uses a generic configuration system that works with dicts or objects:

```python
# Dictionary config
config = {
    "AXIOMS_JWKS_URL": "https://auth.example.com/.well-known/jwks.json",
    "AXIOMS_ISS_URL": "https://auth.example.com",
    "AXIOMS_AUDIENCE": "your-api-audience",
    "AXIOMS_DOMAIN": "auth.example.com",  # Alternative to AXIOMS_ISS_URL
}

# Or object config (e.g., from pydantic-settings, django.conf.settings)
class Config:
    AXIOMS_JWKS_URL = "https://auth.example.com/.well-known/jwks.json"
    AXIOMS_AUDIENCE = "your-api-audience"
```

### Configuration Hierarchy

The package follows this hierarchy for JWKS URL:

1. `AXIOMS_JWKS_URL` (if set, used directly)
2. `AXIOMS_ISS_URL + /.well-known/jwks.json`
3. `https://{AXIOMS_DOMAIN} + /.well-known/jwks.json`

## JWKS Manager

The JWKS manager provides:

- **Background refresh**: Periodically fetches JWKS to stay up-to-date with key rotations
- **Caching**: Reduces latency and load on the authorization server
- **Thread-safety**: Safe to use in multi-threaded environments
- **Lazy initialization**: Works without explicit initialization (falls back to on-demand fetch)

### Configuration Options

```python
initialize_jwks_manager(
    jwks_url=None,           # JWKS URL (derived from config if None)
    refresh_interval=3600,   # Refresh every hour (seconds)
    cache_ttl=600,           # Cache TTL: 10 minutes (seconds)
    config=None,             # Configuration dict/object
    prefetch=True            # Pre-fetch JWKS before starting background thread
)
```

## Allowed Algorithms

Only secure asymmetric algorithms are allowed to prevent algorithm confusion attacks:

- RS256, RS384, RS512 (RSA with SHA)
- ES256, ES384, ES512 (ECDSA with SHA)
- PS256, PS384, PS512 (RSA-PSS with SHA)

## Error Handling

The package raises `AxiomsError` for authentication/authorization failures:

```python
from axioms_core.helper import AxiomsError

try:
    payload = check_token_validity(...)
except AxiomsError as e:
    print(f"Error: {e.error}")
    print(f"Status: {e.status_code}")
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src tests

# Lint
ruff check src tests
```

## License

MIT License - see LICENSE file for details.
