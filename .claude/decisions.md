# Ex-Ray — CI/CD Integration Build Plan

> **Purpose**: Implementation guide for Claude Code. This document defines the work to ship Ex-Ray as a CI/CD-integrated tool that delivers SARIF findings to both GitHub code scanning and an MDR analyst pipeline via webhook.
>
> **Prerequisite**: Phase 1 complete. Phase 2 detection rules may or may not be complete — this work is independent and can proceed in parallel.
>
> **Read `CLAUDE.md` before starting.** All behavioral protocols apply.

---

## Context

Ex-Ray currently runs as a local CLI tool producing SARIF, JSON, and text output to stdout or file. This build adds three capabilities:

1. **Webhook delivery** — POST SARIF results to an HTTP endpoint (e.g., Sumo Logic collector)
2. **Tenant tagging** — Inject customer metadata into SARIF so the MDR SIEM can route by customer
3. **GitHub Action packaging** — A reusable GitHub Action so customers add scanning to their repos in minutes

These three pieces close the loop between "scanner produces findings" and "MDR analyst sees an alert."

---

## Decisions

### DEC-CICD-001: Webhook Delivery Flag

**Decision**: Add `--webhook-url` flag to the CLI that HTTP POSTs the SARIF output to a configurable URL.

**Rationale**: This is the single most enabling feature for MDR integration. SARIF is already produced — we just need transport.

**Specification**:

```
exray /path/to/project --format sarif --webhook-url https://collectors.sumologic.com/receiver/v1/http/TOKEN
```

**Implementation Requirements**:

- New module: `src/exray/core/webhook.py`
- Single function: `post_sarif(url: str, sarif_data: dict, tenant_id: str | None, timeout: int = 30) -> bool`
- Use `urllib.request` from stdlib — **no new dependencies** (no `requests`, no `httpx`)
- HTTP POST with `Content-Type: application/json`
- Include `X-Tenant-ID` header if tenant_id is provided
- Include `User-Agent: ex-ray/{version}` header
- Return `True` on 2xx response, `False` otherwise
- Log the HTTP status code and response body on failure
- **Never raise on webhook failure** — scan results should still be written to stdout/file even if the webhook POST fails. Webhook is fire-and-forget with logging.
- Timeout default: 30 seconds
- No retry logic in v1 (keep it simple)

**CLI Integration** (in `cli.py`):

- Add `--webhook-url` option (type: string, default: None)
- After scan completes and SARIF is generated, if `--webhook-url` is set, call `post_sarif()`
- Webhook POST happens **after** normal output (file write or stdout), not instead of it
- Log success: `"SARIF results posted to webhook (HTTP {status_code})"`
- Log failure: `"Webhook delivery failed (HTTP {status_code}): {response_body}"`

**Tests**:

- Unit test `post_sarif()` with mocked HTTP responses (2xx, 4xx, 5xx, timeout, connection error)
- Integration test: CLI with `--webhook-url` flag produces both file output AND webhook POST
- Test that webhook failure does not prevent normal output
- Test `X-Tenant-ID` header presence when tenant_id is set, absence when None

**LOC Budget**: ~60 lines for `webhook.py`, ~15 lines of CLI additions

---

### DEC-CICD-002: Tenant ID Tagging

**Decision**: Add `--tenant-id` flag that injects customer metadata into the SARIF output and webhook headers.

**Rationale**: When the MDR receives SARIF from multiple customers, it needs to know which customer each finding belongs to. This enables SIEM routing, per-customer dashboards, and analyst assignment.

**Specification**:

```
exray /path/to/project --format sarif --tenant-id "acme-corp" --webhook-url https://...
```

**Implementation Requirements**:

**SARIF Injection** (in `reporting.py` or a new helper):

- Add `tenant_id` to the SARIF `run.properties` bag:
  ```json
  {
    "runs": [{
      "properties": {
        "tenantId": "acme-corp"
      },
      "tool": { ... },
      "results": [ ... ]
    }]
  }
  ```
- This is the standard SARIF extension mechanism — `properties` is a property bag for tool-specific metadata
- Also add to `run.properties`: `"scanTimestamp"` (ISO 8601) and `"scannerVersion"` (from package version)

**Webhook Header** (in `webhook.py`):

- Include `X-Tenant-ID: {tenant_id}` header on webhook POST
- This allows SIEM ingestion to route by header without parsing the SARIF body

**CLI Integration**:

- Add `--tenant-id` option (type: string, default: None)
- Pass through to both SARIF generation and webhook delivery
- Tenant ID is optional — scanner works fine without it for standalone use

**Tests**:

- Unit test: SARIF output contains `tenantId` in `run.properties` when flag is set
- Unit test: SARIF output does NOT contain `tenantId` when flag is omitted
- Unit test: Webhook POST includes `X-Tenant-ID` header when set
- Integration test: Full CLI flow with both flags produces correct SARIF and webhook behavior

**LOC Budget**: ~20 lines in reporting, ~5 lines in CLI

---

### DEC-CICD-003: GitHub Action Wrapper

**Decision**: Create a GitHub Action that wraps the Ex-Ray CLI for use in customer CI/CD pipelines.

**Rationale**: A pre-built GitHub Action reduces customer onboarding to copying a workflow file and adding one secret. This is the primary delivery mechanism for MDR customers.

**Implementation**: This is a **separate repository** — `ymlsurgeon/ex-ray-action`

**Action Structure**:

```
ex-ray-action/
├── action.yml              # GitHub Action metadata
├── Dockerfile              # Container action packaging
├── entrypoint.sh           # Thin shell wrapper
├── README.md               # Usage docs with examples
└── .github/
    └── workflows/
        └── test.yml        # Self-test workflow
```

**action.yml**:

```yaml
name: 'Ex-Ray'
description: 'Static analysis scanner for malicious patterns in developer tooling configurations'
branding:
  icon: 'shield'
  color: 'red'

inputs:
  scan_path:
    description: 'Path to scan (defaults to repo root)'
    required: false
    default: '.'
  webhook_url:
    description: 'URL to POST SARIF results to (e.g., Sumo Logic HTTP source)'
    required: false
  tenant_id:
    description: 'Customer/tenant identifier for MDR routing'
    required: false
  severity_threshold:
    description: 'Minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL)'
    required: false
    default: 'LOW'
  format:
    description: 'Output format (sarif, json, text)'
    required: false
    default: 'sarif'
  fail_on_findings:
    description: 'Fail the action if findings are detected (true/false)'
    required: false
    default: 'false'

outputs:
  findings_count:
    description: 'Total number of findings'
  critical_count:
    description: 'Number of CRITICAL findings'
  sarif_file:
    description: 'Path to SARIF output file'

runs:
  using: 'docker'
  image: 'Dockerfile'
```

**Dockerfile**:

```dockerfile
FROM python:3.12-slim
COPY --from=ghcr.io/ymlsurgeon/ex-ray:latest /app /app
# OR: pip install ex-ray (when published to PyPI)
RUN pip install --no-cache-dir ex-ray
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

**entrypoint.sh**:

```bash
#!/bin/bash
set -e

SCAN_PATH="${INPUT_SCAN_PATH:-.}"
FORMAT="${INPUT_FORMAT:-sarif}"
SEVERITY="${INPUT_SEVERITY_THRESHOLD:-LOW}"
SARIF_FILE="/tmp/ex-ray-results.sarif"

# Build command
CMD="exray ${SCAN_PATH} --format ${FORMAT}"

# Optional flags
[ -n "${INPUT_WEBHOOK_URL}" ] && CMD="${CMD} --webhook-url ${INPUT_WEBHOOK_URL}"
[ -n "${INPUT_TENANT_ID}" ] && CMD="${CMD} --tenant-id ${INPUT_TENANT_ID}"
[ -n "${INPUT_SEVERITY_THRESHOLD}" ] && CMD="${CMD} --severity ${INPUT_SEVERITY_THRESHOLD}"

# Always write SARIF to file for GitHub upload
CMD="${CMD} --output ${SARIF_FILE}"

# Run scan
echo "::group::Ex-Ray"
eval ${CMD}
EXIT_CODE=$?
echo "::endgroup::"

# Parse results for outputs
if [ -f "${SARIF_FILE}" ]; then
  FINDINGS=$(python3 -c "import json; d=json.load(open('${SARIF_FILE}')); print(len(d.get('runs',[{}])[0].get('results',[])))")
  CRITICAL=$(python3 -c "import json; d=json.load(open('${SARIF_FILE}')); print(sum(1 for r in d.get('runs',[{}])[0].get('results',[]) if r.get('level')=='error'))")
  echo "findings_count=${FINDINGS}" >> $GITHUB_OUTPUT
  echo "critical_count=${CRITICAL}" >> $GITHUB_OUTPUT
  echo "sarif_file=${SARIF_FILE}" >> $GITHUB_OUTPUT
fi

# Fail if configured and findings exist
if [ "${INPUT_FAIL_ON_FINDINGS}" = "true" ] && [ "${FINDINGS:-0}" -gt "0" ]; then
  echo "::error::Ex-Ray found ${FINDINGS} findings"
  exit 1
fi

exit 0
```

**Customer Workflow Example** (what they copy into their repo):

```yaml
# .github/workflows/dev-trust-scan.yml
name: Ex-Ray
on:
  pull_request:
    paths:
      - 'package.json'
      - 'package-lock.json'
      - '.vscode/tasks.json'
      - '.github/workflows/**'
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Run Ex-Ray
        id: scan
        uses: ymlsurgeon/ex-ray-action@v1
        with:
          webhook_url: ${{ secrets.DTS_WEBHOOK_URL }}
          tenant_id: "customer-acme-corp"
          severity_threshold: "medium"

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scan.outputs.sarif_file }}

      - name: Summary
        if: always()
        run: |
          echo "### Ex-Ray Results" >> $GITHUB_STEP_SUMMARY
          echo "- Total findings: ${{ steps.scan.outputs.findings_count }}" >> $GITHUB_STEP_SUMMARY
          echo "- Critical findings: ${{ steps.scan.outputs.critical_count }}" >> $GITHUB_STEP_SUMMARY
```

**Tests for the Action**:

- Self-test workflow in the action repo that runs against a test fixture repo
- Test with webhook (use a mock endpoint or webhook.site in testing)
- Test SARIF upload to GitHub code scanning
- Test `fail_on_findings` behavior

---

## Implementation Sequence

### Step 1: Webhook Module

**Scope**: `webhook.py` + CLI integration + tests

**Files to create**:
- `src/exray/core/webhook.py`

**Files to modify**:
- `src/exray/cli.py` — add `--webhook-url` and `--tenant-id` options
- `src/exray/core/reporting.py` — add tenant metadata to SARIF properties bag

**Files to create (tests)**:
- `tests/test_webhook.py`
- `tests/test_tenant_metadata.py`

**Acceptance criteria**:
- `exray . --format sarif --webhook-url http://localhost:8080/test` sends SARIF via POST
- `exray . --format sarif --tenant-id acme` includes `tenantId` in SARIF properties
- Both flags together work correctly
- Webhook failure does not block normal output
- All existing tests still pass

**Commit**: `feat(core): add webhook delivery and tenant-id tagging`

### Step 2: End-to-End Validation

**Scope**: Manual and automated integration testing

**Tasks**:
- Create a test fixture directory with known-malicious patterns (reuse existing test fixtures)
- Run full CLI with both new flags against fixtures
- Verify SARIF output structure matches GitHub code scanning expectations
- Verify webhook POST body is valid SARIF with tenant metadata
- Run full test suite — confirm zero regressions

**Commit**: `test(core): add integration tests for webhook and tenant-id`

### Step 3: GitHub Action Repository (separate repo)

**Scope**: Create `ymlsurgeon/ex-ray-action` repository

**Tasks**:
- Create repo structure (action.yml, Dockerfile, entrypoint.sh, README)
- Create self-test workflow
- Test against a fixture repo with deliberately suspicious files
- Write README with usage examples for MDR customers

**Commits**:
- `feat: initial GitHub Action with Docker packaging`
- `test: add self-test workflow with fixture repo`
- `docs: add README with customer onboarding guide`

### Step 4: Proof-of-Concept Test

**Scope**: Full end-to-end test in a real repo

**Tasks**:
- Create a throwaway test repo with:
  - Suspicious `package.json` (preinstall script curling a binary)
  - Malicious `.vscode/tasks.json` (runOn: folderOpen with curl | sh)
  - Suspicious `.github/workflows/` file (if GHA plugin is ready)
- Add the scanner workflow file
- Point webhook at webhook.site (or Sumo Logic free tier) to see raw SARIF arrive
- Open a PR and verify:
  - Scanner runs in GitHub Actions
  - Findings appear as inline annotations on the PR (via SARIF upload)
  - SARIF arrives at webhook endpoint with tenant metadata
  - PR summary step shows finding counts

**This is not committed to the scanner repo — it's a separate test repo.**

---

## Constraints

- **No new dependencies.** `urllib.request` for HTTP. No `requests`, `httpx`, `aiohttp`.
- **Webhook is fire-and-forget.** Never fail the scan because the webhook is down.
- **SARIF format must remain GitHub-compatible.** Test with `github/codeql-action/upload-sarif` to confirm.
- **The GitHub Action repo is separate from the scanner repo.** The action wraps the scanner — it doesn't contain scanner logic.
- **Action must work with the scanner as-is.** If the scanner CLI doesn't support something the action needs, fix the scanner CLI first.

---

## What NOT to Build

- **No authentication/token management.** Webhook URLs contain their own tokens (Sumo Logic HTTP source pattern). No OAuth, no API key management.
- **No retry logic.** v1 is fire-and-forget. Retry can come later if needed.
- **No webhook batching.** One POST per scan run.
- **No custom SARIF transformations.** The MDR SIEM parses standard SARIF. Don't build a translation layer.
- **No GitHub App.** The Action uses `github_token` from the workflow. No GitHub App registration, no OAuth flows.
- **No PyPI publishing yet.** The Dockerfile installs from source. PyPI publishing is a separate task.

---

## Commit Message Format

```
type(scope): short description
```

**Types**: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`
**Scopes**: `core`, `cli`, `action`, `docs`

---

## Checkpoint Summaries

After completing each step, provide:

- What was implemented
- What tests pass (total count and new additions)
- Any concerns, tradeoffs, or deviations
- Ready for next step: yes/no

---

## Success Criteria

This build is complete when:

- [ ] `--webhook-url` flag sends SARIF via HTTP POST
- [ ] `--tenant-id` flag injects metadata into SARIF properties and webhook headers
- [ ] Webhook failure does not block scan output
- [ ] GitHub Action repo exists with working action.yml, Dockerfile, entrypoint.sh
- [ ] Customer workflow example tested end-to-end in a real repo
- [ ] PR annotations appear via GitHub SARIF upload
- [ ] SARIF arrives at webhook endpoint with tenant metadata
- [ ] All existing tests pass (zero regressions)
- [ ] README updated in both repos