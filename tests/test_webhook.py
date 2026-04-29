"""Tests for webhook delivery module."""

import json
import urllib.error
import urllib.request
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from exray.core.webhook import post_findings_ndjson, post_sarif

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


# Sample SARIF with realistic findings for NDJSON tests
SARIF_WITH_FINDINGS = {
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "Ex-Ray",
                "version": "0.1.0",
                "rules": [
                    {"id": "NPM-008", "name": "TruffleHog download", "properties": {"security-severity": "9.5"}},
                    {"id": "NPM-003", "name": "Network calls", "properties": {"security-severity": "5.0"}},
                    {"id": "VSC-001", "name": "Auto-execution", "properties": {"security-severity": "9.5"}},
                    {"id": "GHA-008", "name": "Unpinned action", "properties": {"security-severity": "5.0"}},
                    {"id": "NPM-005", "name": "Filesystem ops", "properties": {"security-severity": "2.0"}},
                ],
            }
        },
        "properties": {
            "scanTimestamp": "2026-04-29T13:50:25+00:00",
            "scannerVersion": "0.1.0",
            "tenantId": "acme-corp",
        },
        "results": [
            {
                "ruleId": "NPM-008",
                "level": "error",
                "message": {"text": "Script downloads TruffleHog binary"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "scripts/setup.js"},
                    "region": {"startLine": 10, "snippet": {"text": "trufflehog/releases"}},
                }}],
                "properties": {"package_name": "devkit-pro", "package_version": "2.1.4"},
            },
            {
                "ruleId": "NPM-003",
                "level": "warning",
                "message": {"text": "Network calls in lifecycle scripts"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "scripts/setup.js"},
                    "region": {"startLine": 11, "snippet": {"text": "https://github.com"}},
                }}],
                "properties": {"package_name": "devkit-pro", "package_version": "2.1.4"},
            },
            {
                "ruleId": "VSC-001",
                "level": "error",
                "message": {"text": "Auto-executing task on folder open"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": ".vscode/tasks.json"},
                    "region": {"startLine": 5, "snippet": {"text": "runOn: folderOpen"}},
                }}],
            },
            {
                "ruleId": "GHA-008",
                "level": "warning",
                "message": {"text": "Unpinned third-party action"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": ".github/workflows/ci.yml"},
                    "region": {"startLine": 12, "snippet": {"text": "uses: some-org/action@v1"}},
                }}],
            },
        ],
    }],
}


def _capture_ndjson_post(sarif_data, tenant_id=None):
    """Helper: call post_findings_ndjson with mocked HTTP, return parsed lines and request."""
    captured = {}

    def fake_urlopen(request, timeout):
        captured["body"] = request.data
        captured["headers"] = dict(request.headers)
        captured["method"] = request.method
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        return mock_response

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        result = post_findings_ndjson("https://example.com/webhook", sarif_data, tenant_id=tenant_id)

    lines = []
    if "body" in captured:
        for line in captured["body"].decode("utf-8").strip().split("\n"):
            lines.append(json.loads(line))
    return result, lines, captured


class TestPostFindingsNdjson:
    """Tests for the post_findings_ndjson() function."""

    def test_ndjson_body_is_valid(self):
        """Each line of the POST body is parseable JSON."""
        result, lines, _ = _capture_ndjson_post(SARIF_WITH_FINDINGS)
        assert result is True
        assert len(lines) == 4  # 4 results in the sample

    def test_all_expected_fields_present(self):
        """First line contains all expected top-level keys."""
        _, lines, _ = _capture_ndjson_post(SARIF_WITH_FINDINGS, tenant_id="acme-corp")
        expected_keys = {
            "source", "version", "tenant_id", "scan_timestamp",
            "rule_id", "rule_name", "severity", "sarif_level",
            "package_name", "package_version",
            "file_path", "line_number", "matched_content", "message",
        }
        assert expected_keys == set(lines[0].keys())

    def test_severity_resolution_from_security_severity(self):
        """security-severity scores map to correct severity strings."""
        _, lines, _ = _capture_ndjson_post(SARIF_WITH_FINDINGS)
        by_rule = {l["rule_id"]: l["severity"] for l in lines}
        assert by_rule["NPM-008"] == "critical"   # 9.5
        assert by_rule["NPM-003"] == "medium"      # 5.0
        assert by_rule["VSC-001"] == "critical"     # 9.5
        assert by_rule["GHA-008"] == "medium"       # 5.0

    def test_package_metadata_on_npm_findings(self):
        """NPM findings include package_name and package_version."""
        _, lines, _ = _capture_ndjson_post(SARIF_WITH_FINDINGS)
        npm_line = next(l for l in lines if l["rule_id"] == "NPM-008")
        assert npm_line["package_name"] == "devkit-pro"
        assert npm_line["package_version"] == "2.1.4"

    def test_package_metadata_null_on_non_npm_findings(self):
        """VSC/GHA findings have null package fields (not missing)."""
        _, lines, _ = _capture_ndjson_post(SARIF_WITH_FINDINGS)
        vsc_line = next(l for l in lines if l["rule_id"] == "VSC-001")
        assert "package_name" in vsc_line
        assert vsc_line["package_name"] is None
        assert vsc_line["package_version"] is None

    def test_matched_content_truncated_at_200(self):
        """matched_content over 200 chars is truncated."""
        sarif = json.loads(json.dumps(SARIF_WITH_FINDINGS))
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] = "x" * 300
        _, lines, _ = _capture_ndjson_post(sarif)
        assert len(lines[0]["matched_content"]) == 200

    def test_empty_results_returns_true_no_post(self):
        """Empty results array returns True without making an HTTP POST."""
        sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Ex-Ray", "rules": []}}, "results": []}]}
        with patch("urllib.request.urlopen") as mock_urlopen:
            result = post_findings_ndjson("https://example.com/webhook", sarif)
        assert result is True
        mock_urlopen.assert_not_called()

    def test_content_type_is_ndjson(self):
        """Content-Type header is application/x-ndjson."""
        _, _, captured = _capture_ndjson_post(SARIF_WITH_FINDINGS)
        assert captured["headers"].get("Content-type") == "application/x-ndjson"

    def test_tenant_id_header_present_when_set(self):
        """X-Tenant-ID header is sent when tenant_id is provided."""
        _, _, captured = _capture_ndjson_post(SARIF_WITH_FINDINGS, tenant_id="acme-corp")
        assert captured["headers"].get("X-tenant-id") == "acme-corp"

    def test_tenant_id_header_absent_when_none(self):
        """X-Tenant-ID header is absent when tenant_id is None and SARIF has no tenantId."""
        sarif = json.loads(json.dumps(SARIF_WITH_FINDINGS))
        del sarif["runs"][0]["properties"]["tenantId"]
        _, _, captured = _capture_ndjson_post(sarif, tenant_id=None)
        assert "X-tenant-id" not in captured["headers"]

    def test_line_count_equals_results_count(self):
        """Number of NDJSON lines equals number of SARIF results."""
        _, lines, _ = _capture_ndjson_post(SARIF_WITH_FINDINGS)
        assert len(lines) == len(SARIF_WITH_FINDINGS["runs"][0]["results"])

    def test_low_severity_resolution(self):
        """security-severity 2.0 maps to 'low'."""
        sarif = json.loads(json.dumps(SARIF_WITH_FINDINGS))
        sarif["runs"][0]["results"] = [{
            "ruleId": "NPM-005",
            "level": "note",
            "message": {"text": "Filesystem ops"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "package.json"},
                "region": {"startLine": 1, "snippet": {"text": "/tmp/"}},
            }}],
        }]
        _, lines, _ = _capture_ndjson_post(sarif)
        assert lines[0]["severity"] == "low"
