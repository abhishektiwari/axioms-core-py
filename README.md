# axioms-core-py

Core JWT authentication and authorization library for Python web frameworks.

## Overview

`axioms-core-py` provides framework-agnostic JWT token validation, JWKS management with background refresh, and claim-based authorization. This is the foundation for framework-specific integrations:

- [axioms-flask-py](https://github.com/abhishektiwari/axioms-flask-py) - Flask integration
- [axioms-fastapi](https://github.com/abhishektiwari/axioms-fastapi) - FastAPI integration
- [axioms-drf-py](https://github.com/abhishektiwari/axioms-drf-py) - Django REST Framework integration

> Note: For most use cases, use one of the framework integrations above instead of using this package directly.

## Supports

- JWT token validation with automatic JWKS retrieval
- Background JWKS refresh with thread-safe caching
- Algorithm validation (only secure asymmetric algorithms allowed)
- Token type validation (typ header)
- Issuer validation (iss claim)
- Claim-based authorization (scopes, roles, permissions)
- Custom claim name support for different authorization servers
- Comprehensive logging with JWT ID (jti) tracking

## Installation

```bash
pip install axioms-core-py
```

## Quick Start

### Configuration

```python
from axioms_core import AxiomsConfig

config = AxiomsConfig(
    AXIOMS_AUDIENCE="your-api-audience",
    AXIOMS_ISS_URL="https://auth.example.com",  # Recommended
    # Or use AXIOMS_DOMAIN for simpler setup:
    # AXIOMS_DOMAIN="auth.example.com",
)
```

### Initialize JWKS Manager (Optional)

For production, initialize at startup to enable background refresh:

```python
from axioms_core import initialize_jwks_manager, shutdown_jwks_manager

# At startup
initialize_jwks_manager(
    config=config,
    refresh_interval=3600,  # Refresh every hour
    cache_ttl=7200,         # Cache for 2 hours
    prefetch=True           # Fetch JWKS immediately
)

# At shutdown (optional - auto-cleanup on exit)
shutdown_jwks_manager()
```

### Token Validation

```python
from axioms_core import get_key_from_jwks_json, check_token_validity
import jwt

# Extract token header
header = jwt.get_unverified_header(token)
kid = header.get("kid")
alg = header.get("alg")

# Get public key from JWKS
key = get_key_from_jwks_json(kid, config)

# Validate token
payload = check_token_validity(
    token=token,
    key=key,
    alg=alg,
    audience=config.AXIOMS_AUDIENCE,
    issuer=config.AXIOMS_ISS_URL,
)

if payload:
    print(f"Valid token for user: {payload.sub}")
```

### Authorization Checks

```python
from axioms_core import check_scopes, check_roles, check_permissions

# Check scopes (space-separated or list)
has_scope = check_scopes(payload.scope, ["read:data"])

# Check roles (list)
has_role = check_roles(payload.roles, ["admin"])

# Check permissions (list)
has_perm = check_permissions(payload.permissions, ["users:read"])
```

## Configuration Options

See `AxiomsConfig` class for all options:

```python
config = AxiomsConfig(
    # Required
    AXIOMS_AUDIENCE="your-api-audience",

    # Recommended (choose one)
    AXIOMS_ISS_URL="https://auth.example.com",
    # AXIOMS_DOMAIN="auth.example.com",
    # AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json",

    # Optional
    AXIOMS_TOKEN_TYPS=["JWT", "at+jwt"],  # Allowed token types
    AXIOMS_SAFE_METHODS=["OPTIONS"],       # HTTP methods to bypass auth

    # JWKS settings
    AXIOMS_JWKS_REFRESH_INTERVAL=3600,     # 1 hour
    AXIOMS_JWKS_CACHE_TTL=7200,            # 2 hours
    AXIOMS_JWKS_PREFETCH=True,

    # Custom claim names (for different auth servers)
    AXIOMS_SCOPE_CLAIMS=["scope", "scp"],
    AXIOMS_ROLES_CLAIMS=["roles", "cognito:groups"],
    AXIOMS_PERMISSIONS_CLAIMS=["permissions"],
)
```

### Configuration Hierarchy

1. `AXIOMS_ISS_URL` → constructs → `AXIOMS_JWKS_URL` (if not set)
2. `AXIOMS_DOMAIN` → constructs → `AXIOMS_ISS_URL` → `AXIOMS_JWKS_URL` (if not set)

## Security

- Allowed algorithms: RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512
- Token type validation: Validates `typ` header against allowed types
- Issuer validation: Validates `iss` claim to prevent token substitution
- Expiration validation: Validates `exp` claim exists and is valid
- Comprehensive logging: All validation failures logged with jti (if available)

## License

MIT License - see LICENSE file for details.
