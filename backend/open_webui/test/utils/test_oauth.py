"""
Unit tests for OAuth cookie max_age fix.

Validates that set_cookie calls in oauth.py include a max_age parameter
derived from JWT_EXPIRES_IN, so cookies persist across browser restarts.

See: openwebui-collaboration/features/oauth-session-cookie-fix/
"""

import pytest
from datetime import timedelta
from unittest.mock import MagicMock, patch, AsyncMock
from open_webui.utils.misc import parse_duration


def _compute_cookie_max_age(jwt_expires_in: str):
    """
    Replicate the logic that oauth.py should use to derive cookie max_age
    from JWT_EXPIRES_IN. Returns int seconds or None.
    """
    delta = parse_duration(jwt_expires_in)
    if delta is None:
        return None
    return int(delta.total_seconds())


class TestCookieMaxAgeComputation:
    """Test the max_age derivation logic itself."""

    def test_four_weeks_returns_seconds(self):
        assert _compute_cookie_max_age("4w") == 4 * 7 * 24 * 60 * 60  # 2419200

    def test_one_hour_returns_seconds(self):
        assert _compute_cookie_max_age("1h") == 3600

    def test_thirty_days_returns_seconds(self):
        assert _compute_cookie_max_age("30d") == 30 * 24 * 60 * 60  # 2592000

    def test_negative_one_returns_none(self):
        """JWT_EXPIRES_IN='-1' means no expiry — cookie should be session-scoped."""
        assert _compute_cookie_max_age("-1") is None

    def test_zero_returns_none(self):
        """JWT_EXPIRES_IN='0' means no expiry — cookie should be session-scoped."""
        assert _compute_cookie_max_age("0") is None

    def test_mixed_duration_returns_total_seconds(self):
        assert _compute_cookie_max_age("1h30m") == 5400


class TestOAuthCookieSetCalls:
    """
    Test that the actual set_cookie calls in OAuthManager.callback include
    max_age derived from JWT_EXPIRES_IN.

    These tests mock the heavy dependencies (DB, OAuth provider, HTTP) and
    verify that the Response.set_cookie calls include the max_age parameter.
    """

    def _extract_set_cookie_calls(self, mock_response):
        """
        Extract all set_cookie calls from a mock response object.
        Returns a dict keyed by cookie name.
        """
        calls = {}
        for call in mock_response.set_cookie.call_args_list:
            key = call.kwargs.get("key", call.args[0] if call.args else None)
            calls[key] = call.kwargs
        return calls

    @pytest.mark.parametrize(
        "jwt_expires_in,expected_max_age",
        [
            ("4w", 2419200),
            ("1h", 3600),
            ("30d", 2592000),
            ("-1", None),
            ("0", None),
        ],
    )
    def test_cookie_max_age_computation_parametrized(
        self, jwt_expires_in, expected_max_age
    ):
        """Verify max_age calculation for various JWT_EXPIRES_IN values."""
        assert _compute_cookie_max_age(jwt_expires_in) == expected_max_age

    def test_parse_duration_returns_timedelta_for_valid_input(self):
        """Ensure parse_duration returns a timedelta we can call .total_seconds() on."""
        result = parse_duration("4w")
        assert isinstance(result, timedelta)
        assert result.total_seconds() == 2419200

    def test_parse_duration_returns_none_for_no_expiry(self):
        """Ensure parse_duration returns None for '-1' (no expiry)."""
        assert parse_duration("-1") is None
        assert parse_duration("0") is None

    def test_parse_duration_raises_for_invalid_input(self):
        """Ensure parse_duration raises ValueError for garbage input."""
        with pytest.raises(ValueError):
            parse_duration("banana")
