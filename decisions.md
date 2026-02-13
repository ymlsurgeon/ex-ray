# Dev Trust Scanner — Phase 2: Detection Rule Expansion

> **Purpose**: Phase 2 implementation guide for Claude Code. This document defines the new detection rules, the GitHub Actions plugin, and the implementation sequence. Reference this file before writing any code.
>
> **Phase 1 Status**: ✅ Complete — 146 tests passing, 94% coverage, 13+ rules deployed, plugin architecture operational.
>
> **Phase 2 Mission**: Expand detection capabilities with 7 new rules targeting active attack campaigns, and ship a new GitHub Actions plugin as a first-class scanning surface.

---

## Phase 2 Scope

### In Scope

- 7 new detection rules (see DEC-P2-001 through DEC-P2-007)
- New `github_actions` plugin (first-class, same standing as `npm_lifecycle` and `vscode_tasks`)
- Test coverage for every new rule against both malicious samples AND known-good packages
- Updated README with new capabilities

### Out of Scope (Deferred)

- Typosquatting detection (`core/typosquatting.py`) — deferred to future phase
- Multi-file correlation logic — deferred to future phase
- Sample corpus testing framework — deferred to future phase
- Automated sample fetching from opensourcemalware.com — deferred to future phase

---

## Detection Rules — Implementation Decisions

### DEC-P2-001: TruffleHog Binary Download Detection

**Priority**: 1 (Highest — actively used in Shai-Hulud campaigns)

**Plugin**: `npm_lifecycle`

**What to detect**: Scripts that download the TruffleHog binary for credential/secret scanning on victim machines.

**Patterns**:

- URLs containing `trufflesecurity/trufflehog` or `trufflehog` binary download paths
- Binary extraction commands following TruffleHog downloads (`tar`, `unzip`, `chmod +x`)
- Execution of downloaded TruffleHog binary (`./trufflehog`, `trufflehog filesystem`, `trufflehog git`)

**Severity**: CRITICAL

**Rule IDs**: NPM-LC-XXX (assign next available sequence numbers)

**Rationale**: TruffleHog is a legitimate tool, but downloading and executing it via npm lifecycle scripts is a strong indicator of credential theft. This is a core technique in the Shai-Hulud worm campaign.

**Remediation guidance**: "This package downloads and executes TruffleHog, a secret-scanning tool. Legitimate packages do not scan your filesystem for credentials during installation. Remove this package immediately and rotate any exposed secrets."

**Test requirements**:

- Fixture with realistic Shai-Hulud-style postinstall script downloading TruffleHog
- Fixture with legitimate package referencing TruffleHog in README/docs (must NOT trigger)
- Validate against top 100 popular npm packages — zero false positives expected

---

### DEC-P2-002: GitHub Actions Workflow Injection Patterns

**Priority**: 2 (Persistence mechanism — Shai-Hulud campaign)

**Plugin**: `github_actions` (NEW PLUGIN — see DEC-P2-008)

**What to detect**: Malicious GitHub Actions workflow files planted by compromised packages or scripts.

**Patterns**:

- Known malicious workflow filenames: `shai-hulud-workflow.yml`, variations
- Workflow files with suspicious triggers: `workflow_dispatch` combined with `schedule` for persistence
- Self-hosted runner registration within workflow files
- Workflow files that download and execute external scripts (`curl | bash`, `wget | sh`)
- Workflows that exfiltrate secrets via environment variable dumping (`env`, `printenv`)
- Suspicious `runs-on: self-hosted` without clear organizational context

**Severity**: CRITICAL for known malicious filenames, HIGH for suspicious patterns

**Rule IDs**: GHA-XXX (new rule ID prefix for GitHub Actions plugin)

**File targets**: `.github/workflows/*.yml`, `.github/workflows/*.yaml`

**Rationale**: Attackers use malicious workflow files for persistence — they execute on push/schedule without developer intervention. The Shai-Hulud campaign specifically plants workflow files that register self-hosted runners.

**Remediation guidance**: "This workflow file contains patterns associated with malicious GitHub Actions injection. Review all workflow files in .github/workflows/ and remove any you did not create. Audit your repository's Actions history for unauthorized runs."

**Test requirements**:

- Fixtures with known Shai-Hulud workflow patterns
- Fixtures with legitimate CI/CD workflows (build, test, deploy) — must NOT trigger
- Fixtures with common open-source workflows (release-please, dependabot) — must NOT trigger
- Edge case: legitimate use of `workflow_dispatch` + `schedule` (e.g., nightly builds)

---

### DEC-P2-003: Repository Creation with Campaign Markers

**Priority**: 3 (Campaign attribution)

**Plugin**: `npm_lifecycle`

**What to detect**: Code that creates GitHub repositories with known malware campaign marker strings.

**Patterns**:

- String literals: `"Shai-Hulud"`, `"Sha1-Hulud"`, `"Sha1-Hulud: The Second Coming"`
- String literals: `"Goldox-T3chs"`, `"Goldox-T3chs: Only Happy Girl"`
- Repository name patterns with `-migration` suffix used as campaign markers
- GitHub API calls (`api.github.com/user/repos`) combined with the above markers
- `git init` + `git remote add` combined with marker strings

**Severity**: CRITICAL

**Rule IDs**: NPM-LC-XXX (assign next available)

**Rationale**: These strings are campaign identifiers used by threat actors to track worm propagation. Their presence in any package is a definitive indicator of compromise.

**Remediation guidance**: "This package contains code that creates GitHub repositories with known malware campaign markers. This is a definitive indicator of the Shai-Hulud supply chain worm. Remove this package immediately, audit your GitHub account for unauthorized repositories, and revoke any GitHub tokens that may have been exposed."

**Test requirements**:

- Fixtures containing each marker string in realistic attack context
- Fixtures with legitimate migration-related package names — must NOT trigger on `-migration` alone
- Fixtures with "Dune" references in comments/docs (the name Shai-Hulud comes from Dune) — must NOT trigger on contextual references, only on code patterns

---

### DEC-P2-004: Docker Privilege Escalation Attempts

**Priority**: 4

**Plugin**: `npm_lifecycle`

**What to detect**: Scripts that attempt Docker socket access or container escape techniques.

**Patterns**:

- Docker socket paths: `/var/run/docker.sock`
- Privileged container flags: `--privileged`, `--cap-add=ALL`, `--cap-add=SYS_ADMIN`
- Docker socket mounting: `-v /var/run/docker.sock`
- Container escape indicators: `nsenter`, `chroot /host`
- Docker API calls to local socket

**Severity**: HIGH

**Rule IDs**: NPM-LC-XXX (assign next available)

**Rationale**: No legitimate npm package should be accessing the Docker socket or requesting elevated container privileges during installation. This indicates either container escape or host compromise attempts.

**Remediation guidance**: "This package attempts to access the Docker daemon socket or use privileged container capabilities. Legitimate npm packages do not require Docker access during installation. Review the script and remove the package if you did not explicitly expect Docker interaction."

**Test requirements**:

- Fixtures with Docker socket access in postinstall scripts
- Fixtures with Docker-related tooling packages (docker-compose wrappers, etc.) — calibrate to avoid false positives on legitimate Docker tools
- Document expected false positive rate for Docker ecosystem packages

---

### DEC-P2-005: Webhook.site Exfiltration Patterns

**Priority**: 5 (Common across many campaigns)

**Plugin**: `npm_lifecycle`

**What to detect**: Data exfiltration to free webhook collection services.

**Patterns**:

- Domains: `webhook.site`, `webhook-test.com`, `requestbin.com`, `pipedream.com`, `hookbin.com`, `requestcatcher.com`
- URL patterns: `https://webhook.site/` followed by UUID
- HTTP requests (`curl`, `wget`, `fetch`, `axios`, `http.request`) targeting these domains
- Encoded/obfuscated versions of these domains (base64, hex, string concatenation)

**Severity**: CRITICAL

**Rule IDs**: NPM-LC-XXX (assign next available)

**Rationale**: Free webhook services are heavily used for exfiltrating stolen credentials, environment variables, and tokens. No legitimate npm package sends data to webhook.site during installation.

**Remediation guidance**: "This package sends data to a webhook collection service (webhook.site or similar). This is a common technique for exfiltrating stolen credentials and environment variables. Remove this package immediately and rotate any tokens or credentials that may have been exposed."

**Test requirements**:

- Fixtures with various webhook exfiltration patterns (curl, fetch, axios)
- Fixtures with obfuscated webhook URLs (base64-encoded domain)
- Fixtures with legitimate webhook documentation/testing packages — calibrate carefully
- Validate no false positives on packages that mention webhook.site in README/docs only

---

### DEC-P2-006: Self-hosted GitHub Runner Installation

**Priority**: 6 (Persistence mechanism)

**Plugin**: `npm_lifecycle` and `github_actions`

**What to detect**: Code that installs GitHub Actions self-hosted runners for persistence.

**Patterns**:

- Runner download URLs: `actions/runner/releases`
- Runner configuration: `config.sh`, `config.cmd` with `--url` and `--token`
- Runner service installation: `svc.sh install`, runner as systemd service
- Runner token requests: API calls to `/actions/runners/registration-token`
- Runner binary execution: `run.sh`, `run.cmd`

**Severity**: CRITICAL

**Rule IDs**: NPM-LC-XXX for npm plugin, GHA-XXX for GitHub Actions plugin

**Rationale**: Installing self-hosted runners gives attackers persistent code execution on victim infrastructure. This is used in Shai-Hulud for maintaining access after initial compromise.

**Remediation guidance**: "This package or workflow installs a GitHub Actions self-hosted runner. Self-hosted runners should only be configured through your organization's official process. An unauthorized runner installation indicates an attempt to establish persistent access to your infrastructure. Remove immediately and audit for any runners registered to your repositories."

**Test requirements**:

- Fixtures with runner installation scripts in npm lifecycle hooks
- Fixtures with workflow files that configure self-hosted runners
- Fixtures with legitimate self-hosted runner setup documentation — must NOT trigger

---

### DEC-P2-007: Preinstall vs Postinstall Timing Analysis

**Priority**: 7

**Plugin**: `npm_lifecycle`

**What to detect**: Packages using `preinstall` scripts, which execute earlier and have wider impact than `postinstall`.

**Patterns**:

- Presence of `preinstall` script in package.json
- Combined with any other suspicious indicator (network calls, encoded strings, file system access)
- `preinstall` scripts that do more than simple validation or environment checks

**Severity**: MEDIUM for `preinstall` presence alone, escalate to HIGH when combined with other indicators

**Rule IDs**: NPM-LC-XXX (assign next available)

**Rationale**: `preinstall` runs before dependencies are installed, giving attackers earlier execution. Most legitimate packages use `postinstall` or `prepare`. The presence of `preinstall` with suspicious content is a stronger signal than `postinstall` with the same content.

**Remediation guidance**: "This package uses a preinstall script, which executes before dependencies are installed. While not inherently malicious, preinstall scripts run earlier in the installation process and are less commonly used by legitimate packages. Review the script contents carefully."

**Test requirements**:

- Fixtures with `preinstall` containing suspicious patterns (higher severity)
- Fixtures with `preinstall` doing legitimate work (environment detection, native compilation checks)
- Fixtures comparing same suspicious content in `preinstall` vs `postinstall` — verify severity difference
- Validate against top 100 npm packages that use `preinstall` legitimately

---

## New Plugin Decision

### DEC-P2-008: GitHub Actions Plugin — First-Class Plugin

**Decision**: Create a new `github_actions` plugin at `src/dev_trust_scanner/plugins/github_actions/` with the same standing and architecture as `npm_lifecycle` and `vscode_tasks`.

**Structure**:

```
src/dev_trust_scanner/plugins/github_actions/
├── __init__.py
├── scanner.py
└── rules/
    └── gha_rules.yaml
```

**Plugin metadata**:

- Name: `github_actions`
- Supported files: `.github/workflows/*.yml`, `.github/workflows/*.yaml`
- Rule ID prefix: `GHA-`

**Scanner responsibilities**:

- Parse YAML workflow files
- Evaluate rules from `gha_rules.yaml`
- Handle malformed YAML gracefully (per DEC-009 — never crash on bad input)
- Report findings with file path, line numbers where possible, matched pattern, and severity

**Design constraints**:

- Same plugin interface as existing plugins: `scan()`, `get_metadata()`, `get_supported_files()`
- Plugin must stay under 300 LOC — shared logic goes to `static_analysis.py`
- No network calls — static analysis only
- Must integrate seamlessly with existing orchestrator and CLI

**Rule ID convention**: `GHA-001`, `GHA-002`, etc.

**Rationale**: GitHub Actions is a premiere attack surface for supply chain attacks. Workflow injection and self-hosted runner abuse are active TTPs in current campaigns. This plugin should be featured prominently in documentation and README.

---

## Implementation Sequence

> **Follow this exact sequence. Do not skip ahead. Commit after each step.**

### Step 1: GitHub Actions Plugin Scaffolding

Create the plugin directory structure, empty `scanner.py` with the plugin interface stubs, empty `gha_rules.yaml`, and `__init__.py`. Register the plugin with the orchestrator. Verify the scanner recognizes the new plugin (runs without errors, reports zero findings).

**Commit**: `feat(gha-plugin): scaffold GitHub Actions plugin with interface stubs`

**Checkpoint**: Run full test suite — all 146 existing tests must pass. New plugin loads without error.

### Step 2: GitHub Actions Detection Rules (DEC-P2-002)

Implement the workflow injection detection rules in `gha_rules.yaml` and wire up `scanner.py` to evaluate them. Start with known malicious filename detection, then add pattern-based rules.

**Commit**: `feat(gha-plugin): implement workflow injection detection rules`

**Checkpoint**: New tests for each GHA rule. Existing tests still pass. Run against sample legitimate workflow files to verify zero false positives.

### Step 3: Self-hosted Runner Rules in GitHub Actions Plugin (DEC-P2-006, GHA portion)

Add runner installation detection rules to `gha_rules.yaml`. These are specific to workflow file context.

**Commit**: `feat(gha-plugin): add self-hosted runner installation detection`

**Checkpoint**: Tests cover runner patterns in workflow files. False positive check against legitimate runner setup documentation.

### Step 4: TruffleHog Binary Download Rules (DEC-P2-001)

Add TruffleHog detection rules to `npm_rules.yaml`. Implement in the npm_lifecycle plugin.

**Commit**: `feat(npm-plugin): add TruffleHog binary download detection`

**Checkpoint**: Tests with Shai-Hulud-style fixtures. Validate against top 100 npm packages.

### Step 5: Webhook.site Exfiltration Rules (DEC-P2-005)

Add webhook exfiltration detection rules to `npm_rules.yaml`. Include obfuscated domain patterns.

**Commit**: `feat(npm-plugin): add webhook.site exfiltration detection`

**Checkpoint**: Tests with various exfiltration patterns. Validate no false positives on webhook documentation packages.

### Step 6: Repository Creation Markers (DEC-P2-003)

Add campaign marker string detection rules to `npm_rules.yaml`.

**Commit**: `feat(npm-plugin): add campaign marker string detection`

**Checkpoint**: Tests for each marker string. Validate no false positives on Dune-related content or legitimate migration packages.

### Step 7: Docker Privilege Escalation Rules (DEC-P2-004)

Add Docker socket and privilege escalation rules to `npm_rules.yaml`.

**Commit**: `feat(npm-plugin): add Docker privilege escalation detection`

**Checkpoint**: Tests for Docker patterns. Document false positive expectations for Docker ecosystem packages.

### Step 8: Self-hosted Runner Rules in npm Plugin (DEC-P2-006, npm portion)

Add runner installation detection to `npm_rules.yaml` for lifecycle script context.

**Commit**: `feat(npm-plugin): add self-hosted runner installation detection in lifecycle scripts`

**Checkpoint**: Tests for runner patterns in postinstall/preinstall scripts.

### Step 9: Preinstall Timing Analysis (DEC-P2-007)

Implement preinstall risk escalation logic. This may require scanner-level logic beyond YAML pattern matching — if `preinstall` is detected, escalate severity of co-occurring findings.

**Commit**: `feat(npm-plugin): add preinstall timing risk analysis`

**Checkpoint**: Tests comparing severity levels. Validate against packages with legitimate preinstall usage.

### Step 10: Integration Testing & Documentation

- Run full test suite — target > 90% coverage
- Scan a set of known-good npm packages — document any false positives
- Update README with new plugin and rule documentation
- Update this decisions.md with any implementation notes or deviations

**Commit**: `docs: update README and decisions.md for Phase 2 capabilities`

**Checkpoint**: All tests pass, coverage > 90%, README reflects current capabilities.

---

## Rule Quality Standards

All new rules MUST meet:

- **False positive rate**: < 1% when scanned against top 100 popular npm packages
- **Severity assignment**: CRITICAL, HIGH, MEDIUM, or LOW — justified in the rule decision
- **Actionable remediation**: Every finding includes clear guidance for the developer
- **Performance**: No single rule should add more than 100ms to scan time
- **Test coverage**: At least one malicious fixture and one benign fixture per rule

---

## Validation Requirements

For each new rule:

1. **Malicious fixture**: Realistic test case based on published threat intelligence
2. **Benign fixture**: Known-good configuration that must NOT trigger the rule
3. **Top 100 validation**: Scan against top 100 popular npm packages — document results
4. **Edge cases**: Document known edge cases and decisions made about them

---

## Threat Intelligence Sources

Rules in this phase are informed by:

- Shai-Hulud npm worm campaign (TruffleHog, workflow injection, runner abuse, campaign markers)
- Contagious Interview VS Code campaign (existing Phase 1 rules cover this)
- Published reports from: ReversingLabs, Wiz Security, GitLab Security, Unit 42, Sonatype

---

## Existing Constraints (Carried from Phase 1)

These constraints remain in full effect:

- **No network calls.** This tool is offline-only. No fetching, no phoning home, no update checks.
- **Do not use `print()`.** Use `logging` or `rich.console`.
- **Do not use `Any` type hints** unless there is a concrete, documented reason.
- **Do not create god classes.** If a class is doing more than one thing, split it.
- **Do not write plugins longer than 300 lines.** Move shared logic to `static_analysis.py`.
- **Do not change the plugin interface** (`scan`, `get_metadata`, `get_supported_files`) without approval.
- **Do not auto-generate rules.** Every detection rule must be intentional and documented with a rationale.
- **Do not silence exceptions.** Catch them, log them, and include them in scan results per DEC-009.
- **Do not refactor decisions.md** unless explicitly asked to.

---

## When to Stop and Ask

### Design questions

- If a rule's pattern matching is ambiguous — stop and ask
- If a rule needs logic beyond YAML pattern matching — describe the approach and wait for approval
- If the GitHub Actions plugin needs to deviate from the existing plugin interface — stop and ask

### Test failures

- If tests fail because the design doesn't work as expected — stop and explain
- Never delete or skip a failing test to move forward

### False positive concerns

- If a rule triggers on a popular legitimate package — stop and report which package and why
- Propose pattern refinement before proceeding

### Scope creep

- If implementing a rule naturally leads to wanting multi-file correlation — stop. That's deferred.
- If implementing a rule naturally leads to wanting typosquatting detection — stop. That's deferred.
- Stay within the 7 defined rules and the GitHub Actions plugin.

---

## Commit Message Format

```
type(scope): short description

[optional body with context]
```

**Types**: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`
**Scopes**: `core`, `npm-plugin`, `vscode-plugin`, `gha-plugin`, `cli`, `docs`

**Examples**:

```
feat(gha-plugin): scaffold GitHub Actions plugin with interface stubs
feat(gha-plugin): implement workflow injection detection rules
feat(npm-plugin): add TruffleHog binary download detection
test(gha-plugin): add false positive validation for legitimate workflows
docs: update README and decisions.md for Phase 2 capabilities
```

---

## Checkpoint Summaries

After completing each step, provide:

- What was implemented
- What tests pass (total count and new additions)
- Any concerns, tradeoffs, or deviations
- Ready for next step: yes/no

---

## Success Criteria

Phase 2 is complete when:

- [ ] All 7 detection rules implemented and tested
- [ ] GitHub Actions plugin operational as first-class scanner
- [ ] Test coverage > 90%
- [ ] Zero regressions on existing 146 tests
- [ ] Each rule validated against known-good packages
- [ ] README updated with new capabilities
- [ ] This document updated with implementation notes