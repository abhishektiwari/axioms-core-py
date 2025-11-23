"""Tests for authorization check functions."""

from axioms_core.helper import (
    check_claims,
    check_permissions,
    check_roles,
    check_scopes,
)


class TestCheckClaims:
    """Test check_claims generic function."""

    def test_string_to_string_or(self):
        """Test OR operation with both string inputs."""
        provided = "read:data write:data admin"
        required = "read:data super:admin"

        assert check_claims(provided, required) is True
        assert check_claims(provided, required, "OR") is True

    def test_string_to_string_and(self):
        """Test AND operation with both string inputs."""
        provided = "read:data write:data admin"
        required = "read:data write:data"

        assert check_claims(provided, required, "AND") is True

        # Missing one required claim
        required = "read:data super:admin"
        assert check_claims(provided, required, "AND") is False

    def test_list_to_list_or(self):
        """Test OR operation with both list inputs."""
        provided = ["admin", "editor", "viewer"]
        required = ["admin", "superuser"]

        assert check_claims(provided, required) is True
        assert check_claims(provided, required, "OR") is True

    def test_list_to_list_and(self):
        """Test AND operation with both list inputs."""
        provided = ["admin", "editor", "viewer"]
        required = ["admin", "editor"]

        assert check_claims(provided, required, "AND") is True

        # Missing one required claim
        required = ["admin", "superuser"]
        assert check_claims(provided, required, "AND") is False

    def test_string_to_list_or(self):
        """Test OR operation with string provided, list required."""
        provided = "read:data write:data admin"
        required = ["read:data", "super:admin"]

        assert check_claims(provided, required) is True

    def test_string_to_list_and(self):
        """Test AND operation with string provided, list required."""
        provided = "read:data write:data admin"
        required = ["read:data", "write:data"]

        assert check_claims(provided, required, "AND") is True

        required = ["read:data", "super:admin"]
        assert check_claims(provided, required, "AND") is False

    def test_list_to_string_or(self):
        """Test OR operation with list provided, string required."""
        provided = ["admin", "editor", "viewer"]
        required = "admin superuser"

        assert check_claims(provided, required) is True

    def test_list_to_string_and(self):
        """Test AND operation with list provided, string required."""
        provided = ["admin", "editor", "viewer"]
        required = "admin editor"

        assert check_claims(provided, required, "AND") is True

        required = "admin superuser"
        assert check_claims(provided, required, "AND") is False

    def test_empty_required_claims_string(self):
        """Test with empty required claims (string)."""
        provided = "read:data write:data"
        required = ""

        assert check_claims(provided, required) is True
        assert check_claims(provided, required, "AND") is True

    def test_empty_required_claims_list(self):
        """Test with empty required claims (list)."""
        provided = ["admin", "editor"]
        required = []

        assert check_claims(provided, required) is True
        assert check_claims(provided, required, "AND") is True

    def test_empty_provided_claims_string(self):
        """Test with empty provided claims (string)."""
        provided = ""
        required = "admin"

        assert check_claims(provided, required) is False
        assert check_claims(provided, required, "AND") is False

    def test_empty_provided_claims_list(self):
        """Test with empty provided claims (list)."""
        provided = []
        required = ["admin"]

        assert check_claims(provided, required) is False
        assert check_claims(provided, required, "AND") is False

    def test_tuple_input(self):
        """Test with tuple input (for frozen Box compatibility)."""
        provided = ("admin", "editor", "viewer")
        required = ["admin", "editor"]

        assert check_claims(provided, required) is True
        assert check_claims(provided, required, "AND") is True

    def test_case_sensitive(self):
        """Test that claim matching is case-sensitive."""
        provided = ["ADMIN", "editor"]
        required = ["admin"]

        assert check_claims(provided, required) is False

    def test_exact_match_or(self):
        """Test OR with exact match."""
        provided = ["read:data", "write:data"]
        required = ["read:data", "write:data"]

        assert check_claims(provided, required) is True

    def test_exact_match_and(self):
        """Test AND with exact match."""
        provided = ["read:data", "write:data"]
        required = ["read:data", "write:data"]

        assert check_claims(provided, required, "AND") is True

    def test_operation_case_insensitive(self):
        """Test that operation parameter is case-insensitive."""
        provided = ["admin", "editor"]
        required = ["admin", "editor"]

        assert check_claims(provided, required, "and") is True
        assert check_claims(provided, required, "And") is True
        assert check_claims(provided, required, "AND") is True
        assert check_claims(provided, required, "or") is True
        assert check_claims(provided, required, "Or") is True
        assert check_claims(provided, required, "OR") is True

    def test_namespace_claims(self):
        """Test with namespaced claims (e.g., from Auth0)."""
        provided = [
            "https://example.com/claims/read",
            "https://example.com/claims/write",
        ]
        required = ["https://example.com/claims/read"]

        assert check_claims(provided, required) is True
        assert check_claims(provided, required, "AND") is True

    def test_no_match_or(self):
        """Test OR operation with no matching claims."""
        provided = ["viewer", "guest"]
        required = ["admin", "editor"]

        assert check_claims(provided, required) is False

    def test_no_match_and(self):
        """Test AND operation with no matching claims."""
        provided = ["viewer", "guest"]
        required = ["admin", "editor"]

        assert check_claims(provided, required, "AND") is False


class TestCheckScopes:
    """Test check_scopes function."""

    def test_scope_present(self):
        """Test when required scope is present."""
        provided = "read:data write:data admin"
        required = ["read:data"]

        assert check_scopes(provided, required) is True

    def test_multiple_scopes_one_present(self):
        """Test when one of multiple required scopes is present."""
        provided = "read:data write:data"
        required = ["admin", "read:data"]

        assert check_scopes(provided, required) is True

    def test_scope_not_present(self):
        """Test when required scope is not present."""
        provided = "read:data write:data"
        required = ["admin"]

        assert check_scopes(provided, required) is False

    def test_empty_required_scopes(self):
        """Test when no scopes are required."""
        provided = "read:data write:data"
        required = []

        assert check_scopes(provided, required) is True

    def test_empty_provided_scopes(self):
        """Test when token has no scopes."""
        provided = ""
        required = ["read:data"]

        assert check_scopes(provided, required) is False

    def test_exact_match(self):
        """Test exact scope matching."""
        provided = "read:data"
        required = ["read:data"]

        assert check_scopes(provided, required) is True

    def test_partial_match_fails(self):
        """Test that partial matches don't work."""
        provided = "read:dat"
        required = ["read:data"]

        assert check_scopes(provided, required) is False

    def test_case_sensitive(self):
        """Test that scope matching is case-sensitive."""
        provided = "READ:DATA"
        required = ["read:data"]

        assert check_scopes(provided, required) is False

    def test_multiple_spaces(self):
        """Test handling of multiple spaces in scope string."""
        provided = "read:data  write:data   admin"
        required = ["admin"]

        assert check_scopes(provided, required) is True


class TestCheckRoles:
    """Test check_roles function."""

    def test_role_present(self):
        """Test when required role is present."""
        provided_roles = ["admin", "editor", "viewer"]
        required_roles = ["admin"]

        assert check_roles(provided_roles, required_roles) is True

    def test_multiple_roles_one_present(self):
        """Test when one of multiple required roles is present."""
        provided_roles = ["editor", "viewer"]
        required_roles = ["admin", "editor"]

        assert check_roles(provided_roles, required_roles) is True

    def test_role_not_present(self):
        """Test when required role is not present."""
        provided_roles = ["viewer"]
        required_roles = ["admin", "editor"]

        assert check_roles(provided_roles, required_roles) is False

    def test_empty_required_roles(self):
        """Test when no roles are required."""
        provided_roles = ["admin"]
        required_roles = []

        assert check_roles(provided_roles, required_roles) is True

    def test_empty_token_roles(self):
        """Test when token has no roles."""
        provided_roles = []
        required_roles = ["admin"]

        assert check_roles(provided_roles, required_roles) is False

    def test_exact_match(self):
        """Test exact role matching."""
        provided_roles = ["admin"]
        required_roles = ["admin"]

        assert check_roles(provided_roles, required_roles) is True

    def test_tuple_input(self):
        """Test with tuple input (frozen Box returns tuples)."""
        provided_roles = ("admin", "editor")
        required_roles = ["admin"]

        assert check_roles(provided_roles, required_roles) is True

    def test_case_sensitive(self):
        """Test that role matching is case-sensitive."""
        provided_roles = ["ADMIN"]
        required_roles = ["admin"]

        assert check_roles(provided_roles, required_roles) is False


class TestCheckPermissions:
    """Test check_permissions function."""

    def test_permission_present(self):
        """Test when required permission is present."""
        provided_permissions = ["users:read", "users:write", "posts:read"]
        required_permissions = ["users:read"]

        assert check_permissions(provided_permissions, required_permissions) is True

    def test_multiple_permissions_one_present(self):
        """Test when one of multiple required permissions is present."""
        provided_permissions = ["users:read", "posts:read"]
        required_permissions = ["users:write", "users:read"]

        assert check_permissions(provided_permissions, required_permissions) is True

    def test_permission_not_present(self):
        """Test when required permission is not present."""
        provided_permissions = ["users:read"]
        required_permissions = ["users:write", "users:delete"]

        assert check_permissions(provided_permissions, required_permissions) is False

    def test_empty_required_permissions(self):
        """Test when no permissions are required."""
        provided_permissions = ["users:read"]
        required_permissions = []

        assert check_permissions(provided_permissions, required_permissions) is True

    def test_empty_token_permissions(self):
        """Test when token has no permissions."""
        provided_permissions = []
        required_permissions = ["users:read"]

        assert check_permissions(provided_permissions, required_permissions) is False

    def test_exact_match(self):
        """Test exact permission matching."""
        provided_permissions = ["users:read"]
        required_permissions = ["users:read"]

        assert check_permissions(provided_permissions, required_permissions) is True

    def test_tuple_input(self):
        """Test with tuple input (frozen Box returns tuples)."""
        provided_permissions = ("users:read", "users:write")
        required_permissions = ["users:read"]

        assert check_permissions(provided_permissions, required_permissions) is True

    def test_case_sensitive(self):
        """Test that permission matching is case-sensitive."""
        provided_permissions = ["USERS:READ"]
        required_permissions = ["users:read"]

        assert check_permissions(provided_permissions, required_permissions) is False

    def test_namespace_permissions(self):
        """Test namespaced permissions (e.g., from Auth0)."""
        provided_permissions = [
            "https://example.com/permissions/read",
            "https://example.com/permissions/write",
        ]
        required_permissions = ["https://example.com/permissions/read"]

        assert check_permissions(provided_permissions, required_permissions) is True


class TestAuthorizationLogic:
    """Test authorization logic (OR semantics)."""

    def test_scopes_or_logic(self):
        """Test that scopes use OR logic (any one is sufficient)."""
        provided = "read:data"
        required = ["admin", "read:data", "write:data"]

        # Only one scope matches, but that's enough
        assert check_scopes(provided, required) is True
        assert check_scopes(provided, required, "OR") is True

    def test_roles_or_logic(self):
        """Test that roles use OR logic (any one is sufficient)."""
        provided_roles = ["editor"]
        required_roles = ["admin", "editor", "owner"]

        # Only one role matches, but that's enough
        assert check_roles(provided_roles, required_roles) is True
        assert check_roles(provided_roles, required_roles, "OR") is True

    def test_permissions_or_logic(self):
        """Test that permissions use OR logic (any one is sufficient)."""
        provided_permissions = ["users:write"]
        required_permissions = ["users:read", "users:write", "users:delete"]

        # Only one permission matches, but that's enough
        assert check_permissions(provided_permissions, required_permissions) is True
        assert (
            check_permissions(provided_permissions, required_permissions, "OR") is True
        )


class TestAndOperationScopes:
    """Test AND operation for scopes (all required)."""

    def test_scopes_and_all_present(self):
        """Test AND operation when all required scopes are present."""
        provided = "read:data write:data admin"
        required = ["read:data", "write:data"]

        assert check_scopes(provided, required, "AND") is True

    def test_scopes_and_exact_match(self):
        """Test AND operation with exact match."""
        provided = "read:data write:data"
        required = ["read:data", "write:data"]

        assert check_scopes(provided, required, "AND") is True

    def test_scopes_and_missing_one(self):
        """Test AND operation when one required scope is missing."""
        provided = "read:data"
        required = ["read:data", "write:data"]

        assert check_scopes(provided, required, "AND") is False

    def test_scopes_and_missing_all(self):
        """Test AND operation when all required scopes are missing."""
        provided = "admin"
        required = ["read:data", "write:data"]

        assert check_scopes(provided, required, "AND") is False

    def test_scopes_and_empty_required(self):
        """Test AND operation with empty required scopes."""
        provided = "read:data"
        required = []

        assert check_scopes(provided, required, "AND") is True

    def test_scopes_and_case_insensitive_operation(self):
        """Test that operation parameter is case-insensitive."""
        provided = "read:data write:data"
        required = ["read:data", "write:data"]

        assert check_scopes(provided, required, "and") is True
        assert check_scopes(provided, required, "And") is True
        assert check_scopes(provided, required, "AND") is True

    def test_scopes_and_single_required(self):
        """Test AND operation with single required scope."""
        provided = "read:data write:data"
        required = ["read:data"]

        assert check_scopes(provided, required, "AND") is True


class TestAndOperationRoles:
    """Test AND operation for roles (all required)."""

    def test_roles_and_all_present(self):
        """Test AND operation when all required roles are present."""
        provided_roles = ["admin", "editor", "viewer"]
        required_roles = ["admin", "editor"]

        assert check_roles(provided_roles, required_roles, "AND") is True

    def test_roles_and_exact_match(self):
        """Test AND operation with exact match."""
        provided_roles = ["admin", "editor"]
        required_roles = ["admin", "editor"]

        assert check_roles(provided_roles, required_roles, "AND") is True

    def test_roles_and_missing_one(self):
        """Test AND operation when one required role is missing."""
        provided_roles = ["admin"]
        required_roles = ["admin", "editor"]

        assert check_roles(provided_roles, required_roles, "AND") is False

    def test_roles_and_missing_all(self):
        """Test AND operation when all required roles are missing."""
        provided_roles = ["viewer"]
        required_roles = ["admin", "editor"]

        assert check_roles(provided_roles, required_roles, "AND") is False

    def test_roles_and_empty_required(self):
        """Test AND operation with empty required roles."""
        provided_roles = ["admin"]
        required_roles = []

        assert check_roles(provided_roles, required_roles, "AND") is True

    def test_roles_and_tuple_input(self):
        """Test AND operation with tuple input (frozen Box)."""
        provided_roles = ("admin", "editor", "viewer")
        required_roles = ["admin", "editor"]

        assert check_roles(provided_roles, required_roles, "AND") is True

    def test_roles_and_single_required(self):
        """Test AND operation with single required role."""
        provided_roles = ["admin", "editor"]
        required_roles = ["admin"]

        assert check_roles(provided_roles, required_roles, "AND") is True


class TestAndOperationPermissions:
    """Test AND operation for permissions (all required)."""

    def test_permissions_and_all_present(self):
        """Test AND operation when all required permissions are present."""
        provided_permissions = ["users:read", "users:write", "users:delete"]
        required_permissions = ["users:read", "users:write"]

        assert (
            check_permissions(provided_permissions, required_permissions, "AND") is True
        )

    def test_permissions_and_exact_match(self):
        """Test AND operation with exact match."""
        provided_permissions = ["users:read", "users:write"]
        required_permissions = ["users:read", "users:write"]

        assert (
            check_permissions(provided_permissions, required_permissions, "AND") is True
        )

    def test_permissions_and_missing_one(self):
        """Test AND operation when one required permission is missing."""
        provided_permissions = ["users:read"]
        required_permissions = ["users:read", "users:write"]

        assert (
            check_permissions(provided_permissions, required_permissions, "AND")
            is False
        )

    def test_permissions_and_missing_all(self):
        """Test AND operation when all required permissions are missing."""
        provided_permissions = ["posts:read"]
        required_permissions = ["users:read", "users:write"]

        assert (
            check_permissions(provided_permissions, required_permissions, "AND")
            is False
        )

    def test_permissions_and_empty_required(self):
        """Test AND operation with empty required permissions."""
        provided_permissions = ["users:read"]
        required_permissions = []

        assert (
            check_permissions(provided_permissions, required_permissions, "AND") is True
        )

    def test_permissions_and_namespace_permissions(self):
        """Test AND operation with namespaced permissions."""
        provided_permissions = [
            "https://example.com/permissions/read",
            "https://example.com/permissions/write",
            "https://example.com/permissions/delete",
        ]
        required_permissions = [
            "https://example.com/permissions/read",
            "https://example.com/permissions/write",
        ]

        assert (
            check_permissions(provided_permissions, required_permissions, "AND") is True
        )

    def test_permissions_and_single_required(self):
        """Test AND operation with single required permission."""
        provided_permissions = ["users:read", "users:write"]
        required_permissions = ["users:read"]

        assert (
            check_permissions(provided_permissions, required_permissions, "AND") is True
        )


class TestOperationComparison:
    """Test comparison between OR and AND operations."""

    def test_scopes_or_vs_and(self):
        """Test difference between OR and AND for scopes."""
        provided = "read:data admin"
        required = ["read:data", "write:data"]

        # OR: True (read:data matches)
        assert check_scopes(provided, required, "OR") is True

        # AND: False (write:data missing)
        assert check_scopes(provided, required, "AND") is False

    def test_roles_or_vs_and(self):
        """Test difference between OR and AND for roles."""
        provided_roles = ["admin", "viewer"]
        required_roles = ["admin", "editor"]

        # OR: True (admin matches)
        assert check_roles(provided_roles, required_roles, "OR") is True

        # AND: False (editor missing)
        assert check_roles(provided_roles, required_roles, "AND") is False

    def test_permissions_or_vs_and(self):
        """Test difference between OR and AND for permissions."""
        provided_permissions = ["users:read", "posts:write"]
        required_permissions = ["users:read", "users:write"]

        # OR: True (users:read matches)
        assert (
            check_permissions(provided_permissions, required_permissions, "OR") is True
        )

        # AND: False (users:write missing)
        assert (
            check_permissions(provided_permissions, required_permissions, "AND")
            is False
        )
