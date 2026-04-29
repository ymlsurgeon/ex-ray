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
        "User-Agent": f"ex-ray/{_VERSION}",
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


def post_findings_ndjson(
    url: str,
    sarif_data: dict,
    tenant_id: str | None = None,
    timeout: int = 30,
) -> bool:
    """
    POST findings as newline-delimited JSON (one line per finding).

    Each finding becomes a flat JSON object with top-level fields.
    Sumo Logic splits NDJSON into individual log lines automatically,
    making every field directly FER-extractable.

    Args:
        url: Full webhook URL
        sarif_data: SARIF dict to flatten and send
        tenant_id: Optional tenant identifier
        timeout: Request timeout in seconds (default 30)

    Returns:
        True on 2xx response, False on any error
    """
    run = sarif_data.get("runs", [{}])[0]
    results = run.get("results", [])

    if not results:
        logger.info("No findings to send via webhook")
        return True

    # Build severity and rule_name lookups from the rules array
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    severity_map: dict[str, str] = {}
    rule_name_map: dict[str, str] = {}
    for rule in rules:
        rid = rule.get("id", "")
        score = float(rule.get("properties", {}).get("security-severity", "0"))
        if score >= 9.0:
            severity_map[rid] = "critical"
        elif score >= 7.0:
            severity_map[rid] = "high"
        elif score >= 4.0:
            severity_map[rid] = "medium"
        else:
            severity_map[rid] = "low"
        rule_name_map[rid] = rule.get("name", "")

    # Extract scan-level metadata
    props = run.get("properties", {})
    meta = {
        "source": "ex-ray",
        "version": run.get("tool", {}).get("driver", {}).get("version", "unknown"),
        "tenant_id": tenant_id or props.get("tenantId"),
        "scan_timestamp": props.get("scanTimestamp", ""),
    }

    # Flatten each finding into a top-level JSON object
    lines = []
    for result in results:
        rule_id = result.get("ruleId", "")
        loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})

        finding = {
            **meta,
            "rule_id": rule_id,
            "rule_name": rule_name_map.get(rule_id, ""),
            "severity": severity_map.get(rule_id, "unknown"),
            "sarif_level": result.get("level", ""),
            "package_name": result.get("properties", {}).get("package_name"),
            "package_version": result.get("properties", {}).get("package_version"),
            "file_path": loc.get("artifactLocation", {}).get("uri", ""),
            "line_number": loc.get("region", {}).get("startLine"),
            "matched_content": (loc.get("region", {}).get("snippet", {}).get("text", ""))[:200],
            "message": (result.get("message", {}).get("text", ""))[:500],
        }
        lines.append(json.dumps(finding, separators=(",", ":")))

    body = "\n".join(lines).encode("utf-8")

    headers = {
        "Content-Type": "application/x-ndjson",
        "User-Agent": f"ex-ray/{meta['version']}",
    }
    if meta["tenant_id"]:
        headers["X-Tenant-ID"] = meta["tenant_id"]

    request = urllib.request.Request(url, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            logger.info(f"NDJSON findings posted to webhook (HTTP {status}, {len(lines)} findings)")
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
