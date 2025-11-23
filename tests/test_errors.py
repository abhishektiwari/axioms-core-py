"""Tests for error handling."""

import pytest

from axioms_core.helper import AxiomsError


class TestAxiomsError:
    """Test AxiomsError exception."""

    def test_error_creation(self):
        """Test creating AxiomsError."""
        error = AxiomsError(
            {"error": "unauthorized_access", "error_description": "Invalid token"}, 401
        )

        assert error.error["error"] == "unauthorized_access"
        assert error.error["error_description"] == "Invalid token"
        assert error.status_code == 401

    def test_error_message(self):
        """Test error message extraction."""
        error = AxiomsError(
            {"error": "unauthorized_access", "error_description": "Invalid token"}, 401
        )

        assert str(error) == "Invalid token"

    def test_error_default_status_code(self):
        """Test default status code is 401."""
        error = AxiomsError(
            {"error": "unauthorized_access", "error_description": "Invalid token"}
        )

        assert error.status_code == 401

    def test_error_custom_status_code(self):
        """Test custom status code."""
        error = AxiomsError(
            {"error": "server_error", "error_description": "Internal server error"}, 500
        )

        assert error.status_code == 500

    def test_error_without_description(self):
        """Test error without error_description."""
        error = AxiomsError({"error": "unauthorized_access"}, 401)

        assert str(error) == "Authentication error"

    def test_error_is_exception(self):
        """Test that AxiomsError is an Exception."""
        error = AxiomsError(
            {"error": "unauthorized_access", "error_description": "Invalid token"}, 401
        )

        assert isinstance(error, Exception)

    def test_error_can_be_raised(self):
        """Test that AxiomsError can be raised and caught."""
        with pytest.raises(AxiomsError) as exc_info:
            raise AxiomsError(
                {"error": "unauthorized_access", "error_description": "Invalid token"},
                401,
            )

        assert exc_info.value.status_code == 401
        assert exc_info.value.error["error"] == "unauthorized_access"
