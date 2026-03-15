"""Tests for webhook delivery module."""

import json
import urllib.error
import urllib.request
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from exray.core.webhook import post_sarif

SAMPLE_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "Ex-Ray"}}, "results": []}],
}


class TestPostSarif:
    """Tests for the post_sarif() function."""

    def test_returns_true_on_2xx(self):
        """2xx response returns True."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = post_sarif("https://example.com/webhook", SAMPLE_SARIF)

        assert result is True

    def test_returns_false_on_4xx(self):
        """4xx response returns False and logs error."""
        http_error = urllib.error.HTTPError(
            url="https://example.com/webhook",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(),
            fp=BytesIO(b"Unauthorized"),
        )

        with patch("urllib.request.urlopen", side_effect=http_error):
            result = post_sarif("https://example.com/webhook", SAMPLE_SARIF)

        assert result is False

    def test_returns_false_on_5xx(self):
        """5xx response returns False."""
        http_error = urllib.error.HTTPError(
            url="https://example.com/webhook",
            code=500,
            msg="Internal Server Error",
            hdrs=MagicMock(),
            fp=BytesIO(b"Server Error"),
        )

        with patch("urllib.request.urlopen", side_effect=http_error):
            result = post_sarif("https://example.com/webhook", SAMPLE_SARIF)

        assert result is False

    def test_returns_false_on_connection_error(self):
        """Connection failure returns False."""
        url_error = urllib.error.URLError(reason="Connection refused")

        with patch("urllib.request.urlopen", side_effect=url_error):
            result = post_sarif("https://example.com/webhook", SAMPLE_SARIF)

        assert result is False

    def test_returns_false_on_timeout(self):
        """Timeout returns False."""
        with patch("urllib.request.urlopen", side_effect=TimeoutError()):
            result = post_sarif("https://example.com/webhook", SAMPLE_SARIF)

        assert result is False

    def test_returns_false_on_unexpected_error(self):
        """Unexpected exceptions return False rather than propagating."""
        with patch("urllib.request.urlopen", side_effect=RuntimeError("unexpected")):
            result = post_sarif("https://example.com/webhook", SAMPLE_SARIF)

        assert result is False

    def test_sends_json_body(self):
        """Request body is JSON-encoded SARIF."""
        captured_request = {}

        def fake_urlopen(request, timeout):
            captured_request["body"] = request.data
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__enter__ = lambda s: s
            mock_response.__exit__ = MagicMock(return_value=False)
            return mock_response

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            post_sarif("https://example.com/webhook", SAMPLE_SARIF)

        decoded = json.loads(captured_request["body"].decode("utf-8"))
        assert decoded == SAMPLE_SARIF

    def test_sets_content_type_header(self):
        """Content-Type header is application/json."""
        captured_request = {}

        def fake_urlopen(request, timeout):
            captured_request["headers"] = dict(request.headers)
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__enter__ = lambda s: s
            mock_response.__exit__ = MagicMock(return_value=False)
            return mock_response

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            post_sarif("https://example.com/webhook", SAMPLE_SARIF)

        assert captured_request["headers"].get("Content-type") == "application/json"

    def test_sets_user_agent_header(self):
        """User-Agent header includes scanner name and version."""
        captured_request = {}

        def fake_urlopen(request, timeout):
            captured_request["headers"] = dict(request.headers)
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__enter__ = lambda s: s
            mock_response.__exit__ = MagicMock(return_value=False)
            return mock_response

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            post_sarif("https://example.com/webhook", SAMPLE_SARIF)

        assert "ex-ray" in captured_request["headers"].get("User-agent", "")

    def test_includes_tenant_id_header_when_set(self):
        """X-Tenant-ID header is sent when tenant_id is provided."""
        captured_request = {}

        def fake_urlopen(request, timeout):
            captured_request["headers"] = dict(request.headers)
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__enter__ = lambda s: s
            mock_response.__exit__ = MagicMock(return_value=False)
            return mock_response

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            post_sarif("https://example.com/webhook", SAMPLE_SARIF, tenant_id="acme-corp")

        assert captured_request["headers"].get("X-tenant-id") == "acme-corp"

    def test_omits_tenant_id_header_when_not_set(self):
        """X-Tenant-ID header is absent when tenant_id is None."""
        captured_request = {}

        def fake_urlopen(request, timeout):
            captured_request["headers"] = dict(request.headers)
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__enter__ = lambda s: s
            mock_response.__exit__ = MagicMock(return_value=False)
            return mock_response

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            post_sarif("https://example.com/webhook", SAMPLE_SARIF, tenant_id=None)

        assert "X-tenant-id" not in captured_request["headers"]
        assert "X-Tenant-Id" not in captured_request["headers"]

    def test_uses_post_method(self):
        """HTTP method is POST."""
        captured_request = {}

        def fake_urlopen(request, timeout):
            captured_request["method"] = request.method
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__enter__ = lambda s: s
            mock_response.__exit__ = MagicMock(return_value=False)
            return mock_response

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            post_sarif("https://example.com/webhook", SAMPLE_SARIF)

        assert captured_request["method"] == "POST"

    def test_default_timeout_is_30(self):
        """Default timeout is 30 seconds."""
        captured_request = {}

        def fake_urlopen(request, timeout):
            captured_request["timeout"] = timeout
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__enter__ = lambda s: s
            mock_response.__exit__ = MagicMock(return_value=False)
            return mock_response

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            post_sarif("https://example.com/webhook", SAMPLE_SARIF)

        assert captured_request["timeout"] == 30

    def test_custom_timeout(self):
        """Custom timeout is passed to urlopen."""
        captured_request = {}

        def fake_urlopen(request, timeout):
            captured_request["timeout"] = timeout
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__enter__ = lambda s: s
            mock_response.__exit__ = MagicMock(return_value=False)
            return mock_response

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            post_sarif("https://example.com/webhook", SAMPLE_SARIF, timeout=10)

        assert captured_request["timeout"] == 10
