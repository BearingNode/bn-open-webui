import jwt
import pytest
from datetime import timedelta
from unittest.mock import patch
from open_webui.utils.auth import create_token


class TestCreateToken:
    """Test token creation with standard JWT claims"""

    @patch("open_webui.utils.auth.WEBUI_URL")
    def test_create_token_includes_standard_claims(self, mock_webui_url):
        """Test that tokens include RFC 9068 standard claims"""
        # Mock WEBUI_URL to return a test value
        mock_webui_url.__str__.return_value = "http://localhost:3000"

        # Create a token with test data
        token = create_token({"id": "test-user-123"})

        # Decode without signature verification to inspect claims
        payload = jwt.decode(token, options={"verify_signature": False})

        # Verify standard OAuth 2.0/OIDC claims are present
        assert payload["sub"] == "test-user-123", "Subject (sub) should match user ID"
        assert (
            payload["iss"] == "http://localhost:3000"
        ), "Issuer (iss) should be WEBUI_URL"
        assert (
            payload["aud"] == "http://localhost:3000"
        ), "Audience (aud) should be WEBUI_URL"
        assert "iat" in payload, "Issued at (iat) claim should be present"
        assert isinstance(payload["iat"], (int, float)), "iat should be a timestamp"

        # Verify backward compatibility - id claim is preserved
        assert payload["id"] == "test-user-123", "Original id claim should be preserved"

        # Verify standard JWT claims
        assert "jti" in payload, "JWT ID (jti) should be present"

    @patch("open_webui.utils.auth.WEBUI_URL")
    def test_create_token_with_expiry(self, mock_webui_url):
        """Test that tokens with expiry include standard claims"""
        mock_webui_url.__str__.return_value = "http://localhost:3000"

        # Create a token with expiry
        token = create_token({"id": "test-user-456"}, expires_delta=timedelta(hours=1))

        # Decode without signature verification
        payload = jwt.decode(token, options={"verify_signature": False})

        # Verify standard claims
        assert payload["sub"] == "test-user-456"
        assert payload["iss"] == "http://localhost:3000"
        assert payload["aud"] == "http://localhost:3000"
        assert "iat" in payload
        assert (
            "exp" in payload
        ), "Expiration (exp) should be present when expires_delta provided"

        # Verify exp is after iat
        assert payload["exp"] > payload["iat"], "Expiration should be after issued time"

    @patch("open_webui.utils.auth.WEBUI_URL")
    def test_create_token_empty_webui_url(self, mock_webui_url):
        """Test token creation when WEBUI_URL is empty"""
        mock_webui_url.__str__.return_value = ""

        # Create a token
        token = create_token({"id": "test-user-789"})

        # Decode without signature verification
        payload = jwt.decode(token, options={"verify_signature": False})

        # Even with empty WEBUI_URL, claims should be present
        assert payload["iss"] == ""
        assert payload["aud"] == ""
        assert payload["sub"] == "test-user-789"

    @patch("open_webui.utils.auth.WEBUI_URL")
    def test_create_token_without_id_field(self, mock_webui_url):
        """Test token creation when data doesn't have 'id' field"""
        mock_webui_url.__str__.return_value = "http://localhost:3000"

        # Create a token without id field
        token = create_token({"other_field": "value"})

        # Decode without signature verification
        payload = jwt.decode(token, options={"verify_signature": False})

        # sub should be None when id is not in data
        assert payload["sub"] is None, "Subject should be None when id is not provided"
        assert payload["iss"] == "http://localhost:3000"
        assert payload["aud"] == "http://localhost:3000"
        assert "iat" in payload
