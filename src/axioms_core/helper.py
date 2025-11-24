"""Framework-agnostic token validation and JWT verification for Axioms authentication.

This module handles JWT token validation, signature verification, JWKS key retrieval,
and claim extraction. It supports configurable claim names to work with different
authorization servers (AWS Cognito, Auth0, Okta, etc.).

This is the core module shared by axioms-fastapi, axioms-drf-py, and axioms-flask-py.
"""

import logging
from typing import Any, Dict, List, Optional, Union

import jwt
from box import Box
from jwcrypto import jwk

from .config import get_config_value
from .errors import AxiomsError
from .jwks import _jwks_manager

logger = logging.getLogger(__name__)


# Allowed signature algorithms for JWT validation
# Only asymmetric algorithms are allowed to prevent algorithm confusion attacks
ALLOWED_ALGORITHMS = frozenset(
    [
        "RS256",
        "RS384",
        "RS512",  # RSA with SHA-256, SHA-384, SHA-512
        "ES256",
        "ES384",
        "ES512",  # ECDSA with SHA-256, SHA-384, SHA-512
        "PS256",
        "PS384",
        "PS512",  # RSA-PSS with SHA-256, SHA-384, SHA-512
    ]
)


def validate_token_header(
    token: str,
    allowed_token_typs: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Validate JWT token header and extract algorithm and key ID.

    Validates that the token header contains:
    - A valid algorithm from ALLOWED_ALGORITHMS (prevents algorithm confusion attacks)
    - A key ID (kid) for JWKS key lookup
    - A valid token type (typ) if present

    Args:
        token: JWT token string to validate.
        allowed_token_typs: Optional list of allowed token types.
            Defaults to ["JWT", "jwt", "at+jwt", "application/jwt"].

    Returns:
        dict: Token header containing 'alg', 'kid', and optionally 'typ'.

    Raises:
        AxiomsError: If token header is invalid, malformed, has invalid algorithm,
                    is missing key ID, or has invalid token type.
    """
    if allowed_token_typs is None:
        allowed_token_typs = ["JWT", "jwt", "at+jwt", "application/jwt"]

    try:
        header = jwt.get_unverified_header(token)
    except jwt.DecodeError as e:
        logger.warning(f"Token header decode failed: {e}")
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Malformed token header",
            },
            401,
        )
    except Exception as e:
        logger.error(f"Token header validation failed: {e}")
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Invalid token header",
            },
            401,
        )

    # Validate algorithm
    alg = header.get("alg")
    if not alg:
        logger.warning("Token header missing algorithm")
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Token header missing algorithm",
            },
            401,
        )

    if alg not in ALLOWED_ALGORITHMS:
        logger.warning(
            f"Token algorithm validation failed: {alg} not in ALLOWED_ALGORITHMS"
        )
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": f"Invalid or unsupported algorithm: {alg}",
            },
            401,
        )

    # Validate key ID presence
    kid = header.get("kid")
    if not kid:
        logger.warning("Token header missing key ID")
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Token header missing key ID",
            },
            401,
        )

    # Validate token type (typ) if present
    typ = header.get("typ")
    if typ and typ not in allowed_token_typs:
        logger.warning(
            f"Token type validation failed: typ={typ} not in "
            f"allowed_token_typs={allowed_token_typs}"
        )
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": f"Invalid token type: {typ}",
            },
            401,
        )

    return header


def check_token_validity(
    token: str,
    key,
    alg: str,
    audience: str,
    issuer: Optional[str] = None,
) -> Box:
    """Check token validity including expiry, audience, and issuer.

    Validates JWT token with comprehensive security checks:
    - Signature verification using JWKS public key
    - Algorithm validation (only secure asymmetric algorithms allowed)
    - Expiration time (exp claim must exist and be valid)
    - Audience (aud claim must match provided audience)
    - Issuer (iss claim validated if issuer provided)
    - Issued at time (iat claim)
    - Not before time (nbf claim if present)

    Note:
        Token header validation (algorithm, kid, typ) should be performed separately
        using validate_token_header() before calling this function.

    Args:
        token: JWT token string to validate.
        key: JWK key for verification.
        alg: Algorithm from token header (already validated against ALLOWED_ALGORITHMS).
        audience: Expected audience value.
        issuer: Optional expected issuer value.

    Returns:
        Box: Immutable (frozen) Box containing validated payload.

    Raises:
        AxiomsError: If token validation fails, with RFC 6750 compliant error details.
    """
    try:
        # Convert JWK to PyJWT-compatible key
        key_json = key.export_public()
        algorithm = jwt.algorithms.get_default_algorithms()[alg]
        pyjwt_key = algorithm.from_jwk(key_json)

        # Build decode options
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": True,
            "verify_iss": False,  # We'll handle this conditionally
            "verify_iat": True,
            "verify_nbf": True,
            "require_exp": True,
        }

        # Enable issuer validation if provided
        if issuer:
            options["verify_iss"] = True

        # Decode and verify token
        # Use ALLOWED_ALGORITHMS for defense-in-depth against algorithm confusion attacks
        decoded = jwt.decode_complete(
            token,
            pyjwt_key,
            algorithms=list(ALLOWED_ALGORITHMS),
            audience=audience,
            issuer=issuer,
            options=options,
        )

        payload = decoded["payload"]
        jti = payload.get("jti")
        jti_info = f" jti={jti}" if jti else ""

        # Explicitly verify exp claim exists
        if "exp" not in payload:
            logger.warning(
                f"Token validation failed: exp claim missing from payload{jti_info}"
            )
            raise AxiomsError(
                {
                    "error": "invalid_token",
                    "error_description": "Token missing expiration claim",
                },
                401,
            )

        # Return immutable Box to prevent payload modification
        return Box(payload, frozen_box=True)

    except AxiomsError:
        # Re-raise AxiomsError as-is
        raise
    except jwt.ExpiredSignatureError as e:
        logger.warning(f"Token validation failed: expired signature - {e}")
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Token has expired",
            },
            401,
        )
    except jwt.InvalidAudienceError as e:
        logger.warning(f"Token validation failed: invalid audience - {e}")
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Invalid token audience",
            },
            401,
        )
    except jwt.InvalidIssuerError as e:
        logger.warning(f"Token validation failed: invalid issuer - {e}")
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Invalid token issuer",
            },
            401,
        )
    except jwt.InvalidSignatureError as e:
        logger.warning(f"Token validation failed: invalid signature - {e}")
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Invalid token signature",
            },
            401,
        )
    except jwt.DecodeError as e:
        logger.warning(f"Token validation failed: decode error - {e}")
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Malformed token",
            },
            401,
        )
    except jwt.InvalidTokenError as e:
        logger.warning(f"Token validation failed: invalid token - {e}")
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Invalid access token",
            },
            401,
        )
    except Exception as e:
        logger.error(f"Token validation failed: unexpected error - {e}")
        raise AxiomsError(
            {
                "error": "server_error",
                "error_description": "Token validation error",
            },
            500,
        )


def check_claims(
    provided_claims: Union[str, List[str]],
    required_claims: Union[str, List[str]],
    operation: str = "OR",
) -> bool:
    """Generic function to check if required claims are present in provided claims.

    This is the core authorization function used by check_scopes, check_roles,
    and check_permissions. It handles both string (space-separated) and list formats.

    Args:
        provided_claims: Claims from the token. Can be:
                        - Space-separated string (e.g., "read:data write:data")
                        - List of strings (e.g., ["admin", "editor"])
        required_claims: Required claims to check. Can be:
                        - Space-separated string (e.g., "read:data write:data")
                        - List of strings (e.g., ["admin", "editor"])
        operation: Authorization operation - "OR" (any one required) or "AND" (all required).
                   Defaults to "OR". Case-insensitive.

    Returns:
        bool: True if authorization check passes based on operation:
              - OR: True if any required claim is present (intersection check)
              - AND: True if all required claims are present (subset check)

    Example:
        Basic::

            # With space-separated strings
            check_claims("read:data write:data", "read:data admin")  # True (OR)
            check_claims("read:data", "read:data write:data", "AND")  # False

            # With lists
            check_claims(["admin", "editor"], ["admin"])  # True (OR)
            check_claims(["admin"], ["admin", "editor"], "AND")  # False

            # Mixed formats
            check_claims("read:data write:data", ["read:data", "write:data"], "AND")  # True
    """
    # Handle empty required claims
    if not required_claims:
        return True

    # Convert provided claims to set
    if isinstance(provided_claims, str):
        provided_set = set(provided_claims.split())
    else:
        provided_set = set(provided_claims)

    # Convert required claims to set
    if isinstance(required_claims, str):
        required_set = set(required_claims.split())
    else:
        required_set = set(required_claims)

    # Apply operation
    if operation.upper() == "AND":
        # All required claims must be present (subset check)
        return required_set.issubset(provided_set)
    else:
        # Any one of the required claims is sufficient (intersection check)
        return len(provided_set.intersection(required_set)) > 0


def check_scopes(
    provided_scopes: str, required_scopes: List[str], operation: str = "OR"
) -> bool:
    """Check if required scopes are present in provided scopes.

    This is a convenience wrapper around check_claims() for scope checking.

    Args:
        provided_scopes: Space-separated string of scopes from the token.
        required_scopes: List of required scope strings.
        operation: Authorization operation - "OR" (any one required) or "AND" (all required).
                   Defaults to "OR".

    Returns:
        bool: True if authorization check passes based on operation.

    Example:
        Basic::

            check_scopes("read:data write:data", ["read:data", "admin"])  # True
            check_scopes("read:data write:data", ["read:data", "write:data"], "AND")  # True
    """
    return check_claims(provided_scopes, required_scopes, operation)


def check_roles(
    provided_roles: List[str], required_roles: List[str], operation: str = "OR"
) -> bool:
    """Check if required roles are present in provided roles.

    This is a convenience wrapper around check_claims() for role checking.

    Args:
        provided_roles: List of roles from the token.
        required_roles: List of required role strings.
        operation: Authorization operation - "OR" (any one required) or "AND" (all required).
                   Defaults to "OR".

    Returns:
        bool: True if authorization check passes based on operation.

    Example:
        Basic::

            check_roles(["editor", "viewer"], ["admin", "editor"])  # True
            check_roles(["admin", "editor"], ["admin", "editor"], "AND")  # True
    """
    return check_claims(provided_roles, required_roles, operation)


def check_permissions(
    provided_permissions: List[str],
    required_permissions: List[str],
    operation: str = "OR",
) -> bool:
    """Check if required permissions are present in provided permissions.

    This is a convenience wrapper around check_claims() for permission checking.

    Args:
        provided_permissions: List of permissions from the token.
        required_permissions: List of required permission strings.
        operation: Authorization operation - "OR" (any one required) or "AND" (all required).
                   Defaults to "OR".

    Returns:
        bool: True if authorization check passes based on operation.

    Example:
        Basic::

            perms = ["users:read", "users:write"]
            check_permissions(perms, ["users:write", "users:read"])  # True
            check_permissions(perms, perms, "AND")  # True
    """
    return check_claims(provided_permissions, required_permissions, operation)


def get_claim_names(
    claim_type: str, config: Optional[Union[Dict[str, Any], Any]] = None
) -> List[str]:
    """Get list of claim names to check for a given claim type.

    Checks configuration for custom claim names, falling back to defaults.

    Args:
        claim_type: Type of claim ('SCOPE', 'ROLES', or 'PERMISSIONS').
        config: Optional configuration dict or object.

    Returns:
        list: List of claim names to check in priority order.

    Example:
        Basic::

            get_claim_names('ROLES')
            # Returns: ['roles']

            config = AxiomsConfig(AXIOMS_ROLES_CLAIMS=['role', 'roles'])
            get_claim_names('ROLES', config)
            # Returns: ['role', 'roles']
    """
    # Map claim types to config attribute names (matching axioms-fastapi/drf naming)
    claim_attr_map = {
        "SCOPE": "AXIOMS_SCOPE_CLAIMS",
        "ROLES": "AXIOMS_ROLES_CLAIMS",
        "PERMISSIONS": "AXIOMS_PERMISSIONS_CLAIMS",
    }

    list_attr = claim_attr_map.get(claim_type.upper())
    if list_attr:
        claims = get_config_value(config, list_attr)
        if claims is not None:
            return claims if isinstance(claims, list) else [claims]

    # Default claim names
    defaults = {"SCOPE": ["scope"], "ROLES": ["roles"], "PERMISSIONS": ["permissions"]}

    return defaults.get(claim_type.upper(), [])


def get_claim_from_token(
    payload: Box, claim_type: str, config: Optional[Union[Dict[str, Any], Any]] = None
) -> Any:
    """Extract claim value from token payload.

    Checks multiple possible claim names based on configuration,
    returning the first non-None value found. Handles both string and list/tuple formats.

    Args:
        payload: Decoded JWT token payload (Box object).
        claim_type: Type of claim ('SCOPE', 'ROLES', or 'PERMISSIONS').
        config: Optional configuration dict or object.

    Returns:
        The claim value if found, None otherwise. For SCOPE claims in list/tuple format,
        returns a space-separated string.

    Example:
        Basic::

            get_claim_from_token(payload, 'ROLES')
            # Returns: ['admin', 'editor'] or ('admin', 'editor') for frozen Box

            get_claim_from_token(payload, 'SCOPE')
            # Returns: 'openid profile' (converted from list/tuple if needed)
    """
    for claim_name in get_claim_names(claim_type, config):
        value = getattr(
            payload,
            claim_name.replace(":", "_").replace("/", "_").replace("-", "_"),
            None,
        )
        if value is None:
            # Try with original claim name (for standard claims)
            try:
                value = payload.get(claim_name)
            except (AttributeError, KeyError):
                value = None
        if value is not None:
            # Handle list/tuple format for scopes (frozen Box converts lists to tuples)
            if claim_type.upper() == "SCOPE" and isinstance(value, (list, tuple)):
                return " ".join(value)
            return value
    return None


def get_token_scopes(
    payload: Box, config: Optional[Union[Dict[str, Any], Any]] = None
) -> Optional[str]:
    """Extract scopes from token payload as space-separated string.

    Args:
        payload: Decoded JWT token payload (Box object).
        config: Optional configuration dict or object.

    Returns:
        Space-separated string of scopes, or None if not found.

    Example:
        Basic::

            get_token_scopes(payload)
            # Returns: 'openid profile email'
    """
    return get_claim_from_token(payload, "SCOPE", config)


def get_token_roles(
    payload: Box, config: Optional[Union[Dict[str, Any], Any]] = None
) -> Optional[List[str]]:
    """Extract roles from token payload as list.

    Args:
        payload: Decoded JWT token payload (Box object).
        config: Optional configuration dict or object.

    Returns:
        List of roles, or None if not found.

    Example:
        Basic::

            get_token_roles(payload)
            # Returns: ['admin', 'editor']
    """
    roles = get_claim_from_token(payload, "ROLES", config)
    # Convert tuple to list for frozen Box
    if isinstance(roles, tuple):
        return list(roles)
    return roles


def get_token_permissions(
    payload: Box, config: Optional[Union[Dict[str, Any], Any]] = None
) -> Optional[List[str]]:
    """Extract permissions from token payload as list.

    Args:
        payload: Decoded JWT token payload (Box object).
        config: Optional configuration dict or object.

    Returns:
        List of permissions, or None if not found.

    Example:
        Basic::

            get_token_permissions(payload)
            # Returns: ['users:read', 'users:write']
    """
    permissions = get_claim_from_token(payload, "PERMISSIONS", config)
    # Convert tuple to list for frozen Box
    if isinstance(permissions, tuple):
        return list(permissions)
    return permissions


def get_expected_issuer(
    config: Optional[Union[Dict[str, Any], Any]] = None,
) -> Optional[str]:
    """Get expected issuer URL from configuration.

    Checks for AXIOMS_ISS_URL first, then constructs from AXIOMS_DOMAIN.
    The issuer is used to validate the 'iss' claim in JWT tokens.

    Args:
        config: Optional configuration dict or object.

    Returns:
        str or None: Expected issuer URL (e.g., 'https://auth.example.com'),
                     or None if neither AXIOMS_ISS_URL nor AXIOMS_DOMAIN is configured.

    Example:
        Basic::

            config = AxiomsConfig(
                AXIOMS_ISS_URL="https://auth.example.com/oauth2"
            )
            get_expected_issuer(config)
            # Returns: 'https://auth.example.com/oauth2'

            config = AxiomsConfig(
                AXIOMS_DOMAIN="auth.example.com"
            )
            get_expected_issuer(config)
            # Returns: 'https://auth.example.com'
    """
    # Check for explicit issuer URL first
    iss_url = get_config_value(config, "AXIOMS_ISS_URL")
    if iss_url:
        return iss_url

    # Construct from domain if available
    domain = get_config_value(config, "AXIOMS_DOMAIN")
    if domain:
        # Remove protocol if present
        domain = domain.replace("https://", "").replace("http://", "")
        return f"https://{domain}"

    return None


def get_jwks_url(config: Optional[Union[Dict[str, Any], Any]] = None) -> str:
    """Get JWKS URL from configuration.

    Checks for AXIOMS_JWKS_URL first, then constructs URL from AXIOMS_ISS_URL.
    If AXIOMS_ISS_URL is not set, it will be derived from AXIOMS_DOMAIN.

    Configuration hierarchy:
        1. AXIOMS_JWKS_URL (if set, used directly)
        2. AXIOMS_ISS_URL + /.well-known/jwks.json
        3. https://{AXIOMS_DOMAIN} + /.well-known/jwks.json (via AXIOMS_ISS_URL)

    Args:
        config: Optional configuration dict or object.

    Returns:
        str: Full JWKS URL.

    Raises:
        Exception: If JWKS URL cannot be determined from configuration.
    """
    # Check for explicit JWKS URL first
    jwks_url = get_config_value(config, "AXIOMS_JWKS_URL")
    if jwks_url:
        return jwks_url

    # Construct from issuer URL
    issuer_url = get_expected_issuer(config)
    if issuer_url:
        return f"{issuer_url}/.well-known/jwks.json"

    raise Exception(
        "Please set either AXIOMS_JWKS_URL, AXIOMS_ISS_URL, or AXIOMS_DOMAIN in your config. "
        "For more details review axioms documentation."
    )


def get_key_from_jwks_json(
    kid: str, config: Optional[Union[Dict[str, Any], Any]] = None
) -> Any:
    """Retrieve public key from JWKS endpoint for token verification.

    Uses the global JWKS manager for caching and background refresh if initialized.
    If the manager is not initialized, falls back to on-demand fetching with warning.

    For best performance, initialize the JWKS manager on application startup:
        - Sync frameworks: Use initialize_jwks_manager()
        - Async frameworks: Use initialize_async_jwks_manager()

    Args:
        kid: Key ID from the JWT header.
        config: Optional configuration dict or object.

    Returns:
        JWK: JSON Web Key for signature verification.

    Raises:
        AxiomsError: If key cannot be retrieved or is invalid.
    """
    try:
        jwks_url = get_jwks_url(config)

        # Warn if JWKS manager not initialized (fallback to on-demand fetch)
        if not _jwks_manager._running:
            logger.warning(
                "JWKS manager not initialized. Using on-demand fetch with simple caching. "
                "For better performance and non-blocking background refresh, "
                "call initialize_jwks_manager() or initialize_async_jwks_manager() "
                "during application startup."
            )

        data = _jwks_manager.get_jwks(jwks_url)
        key = jwk.JWKSet().from_json(data).get_key(kid)

        # jwcrypto returns None if key not found
        if key is None:
            raise AxiomsError(
                {
                    "error": "invalid_token",
                    "error_description": "Invalid access token",
                },
                401,
            )

        return key
    except AxiomsError:
        # Re-raise AxiomsError as-is (e.g., invalid URL scheme)
        raise
    except Exception:
        raise AxiomsError(
            {
                "error": "invalid_token",
                "error_description": "Invalid access token",
            },
            401,
        )
