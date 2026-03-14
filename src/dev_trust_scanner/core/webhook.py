"""Webhook delivery for SARIF scan results."""

import json
import logging
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

_VERSION = "0.1.0"


def post_sarif(
    url: str,
    sarif_data: dict,
    tenant_id: str | None = None,
    timeout: int = 30,
) -> bool:
    """
    POST SARIF results to a webhook endpoint.

    Fire-and-forget: logs on failure but never raises. Caller should
    check the return value if delivery confirmation is needed.

    Args:
        url: Full webhook URL (e.g., Sumo Logic HTTP source URL)
        sarif_data: SARIF dict to send as JSON body
        tenant_id: Optional tenant identifier added as X-Tenant-ID header
        timeout: Request timeout in seconds (default 30)

    Returns:
        True on 2xx response, False on any error
    """
    body = json.dumps(sarif_data).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"dev-trust-scanner/{_VERSION}",
    }
    if tenant_id:
        headers["X-Tenant-ID"] = tenant_id

    request = urllib.request.Request(url, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            logger.info(f"SARIF results posted to webhook (HTTP {status})")
            return True

    except urllib.error.HTTPError as e:
        try:
            response_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            response_body = "<unreadable>"
        logger.error(f"Webhook delivery failed (HTTP {e.code}): {response_body}")
        return False

    except urllib.error.URLError as e:
        logger.error(f"Webhook delivery failed (connection error): {e.reason}")
        return False

    except TimeoutError:
        logger.error(f"Webhook delivery failed (timeout after {timeout}s)")
        return False

    except Exception as e:
        logger.error(f"Webhook delivery failed (unexpected error): {e}")
        return False