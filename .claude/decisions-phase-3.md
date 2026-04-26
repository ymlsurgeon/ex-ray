# Ex-Ray — Phase 3 Detection Rules Build Plan

> **Purpose**: Implementation guide for Claude Code. This document defines new detection rules and one scanner enhancement responding to March/April 2026 supply chain incidents (TeamPCP/Trivy, Axios compromise, Contagious Interview evolution).
>
> **Prerequisite**: Phase 2 complete. All 3 plugins operational, 270 tests passing, 91% coverage.
>
> **Read `CLAUDE.md` before starting.** All behavioral protocols apply.

---

## Context

Three recent incidents exposed gaps in Ex-Ray's detection coverage that can be closed **without new plugins or architecture changes**:

1. **TeamPCP/Trivy (Mar 19, 2026)**: Attackers force-pushed malicious code to 76/77 mutable GitHub Action version tags (`@v1`, `@latest`). Repos using unpinned Action references silently pulled compromised code. Lesson: flag unpinned Action references as a hygiene finding.

2. **Shai-Hulud 3.0 (Dec 2025) + TeamPCP CanisterWorm**: Destructive fallback — if exfiltration fails, the malware wipes the victim's home directory (`rm -rf ~/`, `shred`). Lesson: detect destructive commands in lifecycle scripts.

3. **Contagious Interview "Fake Font" (Nov 2025–present)**: DPRK actors disguise JavaScript payloads as font files (`.woff2`, `.ttf`) and execute them via VS Code tasks: `node public/fonts/fa-brands-regular.woff2`. Lesson: flag when `node` executes a file with a non-JavaScript extension.

All three fit inside existing plugins. No new modules, no new dependencies, no architecture changes.

---

## Decisions

### DEC-P3-001: Unpinned GitHub Action Reference Detection

**Decision**: Add rule GHA-008 to `gha_rules.yaml` that flags GitHub Action `uses:` directives referencing mutable tags instead of commit SHAs.

**Rationale**: The TeamPCP attack succeeded because workflows used `uses: aquasecurity/trivy-action@v1` — a mutable tag the attacker force-pushed to malicious code. Pinning to a full SHA (`@abc123def...`) is the only defense against tag mutation. This is also a CISA and GitHub recommended best practice.

**Detection logic**:

- **Match**: `uses:` directives with a tag reference (`@v1`, `@v2.3`, `@main`, `@latest`, `@master`)
- **Exclude**: `uses:` directives with a full 40-character SHA (`@a1b2c3d4e5f6...`)
- **Exclude**: Local actions (`uses: ./`) and Docker references (`uses: docker://`)
- **Exclude**: `actions/checkout` and `actions/upload-artifact` and other first-party GitHub actions — these are lower risk and flagging them would produce noise. Limit detection to third-party actions only.

**Rule definition**:

```yaml
- id: "GHA-008"
  name: "Unpinned third-party GitHub Action reference"
  severity: "medium"
  description: "Workflow uses a third-party GitHub Action pinned to a mutable tag (e.g., @v1) instead of a commit SHA. Mutable tags can be force-pushed to point to malicious code, as demonstrated in the TeamPCP/Trivy supply chain attack (March 2026)."
  patterns:
    - 'uses:\s+(?!actions/|github/|\./)[\w-]+/[\w.-]+@(?!([0-9a-f]{40}|([0-9a-f]{7})))[^\s]+'
  recommendation: "Pin this Action to a full commit SHA instead of a version tag. Example: replace 'uses: owner/action@v1' with 'uses: owner/action@abc123def456...' . You can find the SHA for a release tag using: git ls-remote https://github.com/owner/action refs/tags/v1"
```

**Important note on regex complexity**: The pattern above is the intent. During implementation, test this regex carefully. If the single-pattern approach is fragile, split into a programmatic check in `scanner.py` instead — parse the `uses:` lines, extract the ref portion after `@`, and check if it's a 40-char hex string. This may be more reliable than a regex-only approach. **If you need to add programmatic logic to the GHA scanner, keep it under 30 lines and do not exceed the 300 LOC plugin limit.** The GHA scanner is currently at 117 LOC so there is plenty of room.

**False positive considerations**:
- First-party GitHub actions (`actions/*`, `github/*`) are excluded — they have stronger security posture
- Local actions (`./`) are excluded — they're part of the repo
- This will flag legitimate third-party actions using `@v1` — this is intentional. The finding is MEDIUM severity with clear remediation guidance. It's a hygiene warning, not a malware alert.

**Tests** (add to `tests/test_github_actions.py`):

1. Workflow with `uses: third-party/action@v1` → triggers GHA-008
2. Workflow with `uses: third-party/action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2` → no finding
3. Workflow with `uses: actions/checkout@v4` → no finding (first-party exclusion)
4. Workflow with `uses: github/codeql-action/upload-sarif@v3` → no finding (first-party exclusion)
5. Workflow with `uses: ./local-action` → no finding (local exclusion)
6. Workflow with `uses: third-party/action@main` → triggers GHA-008
7. Workflow with `uses: third-party/action@latest` → triggers GHA-008
8. Workflow with multiple `uses:` lines, mix of pinned and unpinned → only unpinned trigger

**LOC budget**: ~15 lines in `gha_rules.yaml` (or ~15 YAML + ~25 scanner.py if programmatic)

**Commit**: `feat(gha-plugin): add unpinned action reference detection (GHA-008)`

---

### DEC-P3-002: Destructive Command Detection in npm Lifecycle Scripts

**Decision**: Add rules NPM-020 and NPM-021 to `npm_rules.yaml` that detect destructive filesystem commands in lifecycle scripts.

**Rationale**: Shai-Hulud 3.0 introduced a destructive fallback — if the malware cannot exfiltrate credentials, it wipes the victim's home directory. TeamPCP's CanisterWorm included similar destructive capabilities. These are not stealth operations; they are sabotage patterns that should be flagged at the highest severity.

**Rule definitions**:

```yaml
- id: "NPM-020"
  name: "Destructive filesystem commands in lifecycle script"
  severity: "critical"
  description: "Script contains commands that recursively delete or overwrite files. This pattern was seen in the Shai-Hulud 3.0 campaign (December 2025), which wiped victim home directories when exfiltration failed."
  patterns:
    - "rm\\s+-[a-zA-Z]*r[a-zA-Z]*f.*(?:\\$HOME|~/|\\$\\{HOME\\}|os\\.homedir)"
    - "rm\\s+-[a-zA-Z]*r[a-zA-Z]*f\\s+/"
    - "shred\\s+"
    - "find\\s+.*-delete"
    - "find\\s+.*-exec\\s+rm"
    - "mkfs\\."
    - "dd\\s+if=/dev/(?:zero|urandom|random)\\s+of=/"
  recommendation: "This script contains destructive filesystem commands. Legitimate npm packages never delete files outside their own directory during installation. Remove this package immediately and check for damage to your filesystem."

- id: "NPM-021"
  name: "Home directory targeting in lifecycle script"
  severity: "high"
  description: "Script explicitly targets the user's home directory for file operations beyond normal package behavior."
  patterns:
    - "os\\.homedir\\(\\).*(?:rmSync|unlinkSync|rmdirSync)"
    - "\\$HOME.*rm\\s"
    - "~/\\.(?!npmrc|node).*(?:rm|del|erase)"
    - "readdirSync.*homedir.*unlinkSync"
    - "fs\\.(?:rmSync|rmdirSync).*homedir"
  recommendation: "This script targets your home directory for file operations. Review carefully — legitimate packages should not modify files in your home directory during installation. This pattern is associated with destructive malware payloads."
```

**False positive considerations**:
- NPM-020 uses anchored patterns requiring both the destructive command AND a dangerous target (home dir, root). Plain `rm -rf node_modules` will NOT trigger — the target must be home directory or root.
- NPM-021 targets JS-specific APIs (rmSync, unlinkSync) combined with homedir references. Normal cleanup of `node_modules` or temp files won't match.
- `~/.npmrc` and `~/.node` are excluded from NPM-021 since legitimate packages may read npm config.

**Tests** (add to `tests/test_npm_lifecycle.py`):

1. Script with `rm -rf ~/` → triggers NPM-020 (CRITICAL)
2. Script with `rm -rf $HOME/.config` → triggers NPM-020 (CRITICAL)
3. Script with `shred -u /tmp/secrets.json` → triggers NPM-020 (CRITICAL)
4. Script with `find / -name "*.key" -delete` → triggers NPM-020 (CRITICAL)
5. Script with `fs.rmSync(os.homedir(), {recursive: true})` → triggers NPM-021 (HIGH)
6. Script with `rm -rf node_modules` → does NOT trigger (safe cleanup)
7. Script with `rm -rf /tmp/build` → does NOT trigger (temp dir cleanup)
8. Script with `rm -rf ./dist` → does NOT trigger (local dir cleanup)
9. Script with preinstall + `rm -rf ~/` → triggers NPM-020 AND gets PREINSTALL ESCALATION (already handled by existing escalation logic)

**LOC budget**: ~30 lines in `npm_rules.yaml`

**Commit**: `feat(npm-plugin): add destructive command detection (NPM-020, NPM-021)`

---

### DEC-P3-003: File Extension Mismatch Detection in VS Code Tasks

**Decision**: Add programmatic detection to the vscode-tasks scanner that flags when `node` is invoked with a file that has a non-JavaScript extension.

**Rationale**: The Contagious Interview "Fake Font" campaign executes `node public/fonts/fa-brands-regular.woff2` via tasks.json. The file is JavaScript disguised with a font extension. This is a strong signal — there is no legitimate reason to run `node` against a `.woff2`, `.ttf`, `.png`, `.jpg`, or other binary file extension.

**Detection logic** (programmatic, not YAML regex):

1. For each task command, extract file arguments passed to `node` (reuse pattern from npm plugin's `_extract_script_files`)
2. Check the file extension against an allowlist of legitimate JS extensions: `.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`, `.jsx`, `.tsx`
3. If the extension is NOT in the allowlist AND `node` is the executor → generate a VSC-007 finding

**Rule**:

```yaml
- id: "VSC-007"
  name: "Node.js executing non-JavaScript file"
  severity: "critical"
  description: "A VS Code task runs Node.js against a file with a non-JavaScript extension. This is a signature technique of the DPRK Contagious Interview 'Fake Font' campaign, which disguises JavaScript malware as font files (.woff2, .ttf) or other binary formats."
  # Checked programmatically in scanner.py, not via pattern matching
  recommendation: "Inspect the file contents — it likely contains JavaScript despite its extension. This technique is used to evade casual code review. If the file contains obfuscated JavaScript, treat this as confirmed malware. Remove the repository and do not trust the workspace."
```

**Implementation in `scanner.py`** (add to existing task analysis loop):

```python
# --- File extension mismatch detection ---
# Known-good extensions for node execution
_JS_EXTENSIONS = {'.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx'}

def _check_node_extension_mismatch(self, command: str, ...) -> list[Finding]:
    """Flag node executing non-JS files (Contagious Interview 'Fake Font' pattern)."""
    findings = []
    # Extract: node <filepath>
    node_file_pattern = r'\bnode\s+([^\s;&|"]+\.[a-zA-Z0-9]+)'
    for match in re.finditer(node_file_pattern, command):
        filepath = match.group(1)
        ext = Path(filepath).suffix.lower()
        if ext and ext not in _JS_EXTENSIONS:
            findings.append(Finding(
                rule_id="VSC-007",
                rule_name="Node.js executing non-JavaScript file",
                severity=Severity.CRITICAL,
                file_path=...,
                matched_content=f"node {filepath}",
                description=f"Task executes 'node {filepath}' — the '{ext}' extension is not JavaScript. This matches the DPRK Contagious Interview 'Fake Font' attack pattern where malware is disguised as font/image files.",
                recommendation="Inspect the file contents — it likely contains JavaScript despite its extension. If obfuscated JS is found, treat as confirmed malware.",
                plugin_name=self.get_metadata()["name"],
            ))
    return findings
```

**Call site**: Add to the existing task command analysis loop in `_scan_single_task()`, after the existing rule matching and before the obfuscation checks.

**False positive considerations**:
- Only triggers when `node` is the explicit executor AND the file has a non-JS extension
- Running `node --version`, `node -e "..."`, or `node script.js` will NOT trigger
- `.json` files executed via `node` could be a false positive in rare edge cases — but `node file.json` is itself suspicious. Keep it flagging and note in recommendation.
- The allowlist is inclusive (.ts, .tsx, etc.) to avoid flagging TypeScript execution

**Tests** (add to `tests/test_vscode_tasks.py`):

1. Task with `node public/fonts/fa-brands-regular.woff2` → triggers VSC-007 (CRITICAL)
2. Task with `node malware.png` → triggers VSC-007 (CRITICAL)
3. Task with `node payload.ttf` → triggers VSC-007 (CRITICAL)
4. Task with `node config.exe` → triggers VSC-007 (CRITICAL)
5. Task with `node ./scripts/setup.js` → does NOT trigger (legitimate .js)
6. Task with `node app.mjs` → does NOT trigger (legitimate .mjs)
7. Task with `node index.ts` → does NOT trigger (legitimate .ts)
8. Task with `node -e "console.log('hi')"` → does NOT trigger (inline, no file)
9. Task with `node --version` → does NOT trigger (flag, no file)
10. Task with `node public/fonts/fa-brands-regular.woff2` AND `runOn: folderOpen` → triggers BOTH VSC-001 and VSC-007
11. Verify severity is CRITICAL (this is a known campaign IOC, not speculative)

**LOC budget**: ~25 lines in `scanner.py` (method + call site). Add the VSC-007 rule definition to `vscode_rules.yaml` (~8 lines, marked as programmatically checked like VSC-002).

**Current vscode scanner LOC**: 482. This exceeds the 300 LOC plugin limit from CLAUDE.md. **Do NOT add code without first refactoring.** Extract shared logic (entropy check, base64 check, obfuscation check — the repeated pattern across tasks) into a helper or move to `static_analysis.py`. Target: get scanner.py under 400 LOC after adding the new detection logic. This is a prerequisite refactor, not scope creep.

**Commit**: `feat(vscode-plugin): add file extension mismatch detection (VSC-007)`

---

### DEC-P3-004: Supply Chain Demo Repo Update

**Decision**: Add Fake Font and destructive command samples to `ExpelioKeev/supply-chain-demo`.

**Rationale**: The demo repo should showcase all detection capabilities. New rules need corresponding demo content.

**Changes to supply-chain-demo**:

1. **Add a fake font file**: Create `public/fonts/fa-brands-regular.woff2` containing neutered JavaScript (e.g., `console.log("This is not a font");`). Reference it in `.vscode/tasks.json` as a second task.

2. **Add destructive command to setup.js**: Add a commented section showing the Shai-Hulud 3.0 destructive fallback pattern (neutered — use `echo` instead of actual `rm`):
```javascript
// Shai-Hulud 3.0 fallback pattern (neutered for demo)
// Original: execSync('rm -rf ' + os.homedir());
execSync('echo "DESTRUCTIVE_FALLBACK: would rm -rf ' + homeDir + '"');
```

Wait — this is a demo repo with neutered samples. The rule patterns should still match the string literals in the file even if they're in comments or echo strings. **Verify that the scanner picks up patterns inside comments and string literals.** This is important because real malware doesn't always execute destructively on first pass — it may have the destructive code present but conditionally triggered.

**Tests**: Run `exray` against the updated demo repo and verify all new rules fire.

**Commit**: `feat: add fake font and destructive command demo samples`

---

## Implementation Sequence

### Step 1: YAML Rules (GHA-008, NPM-020, NPM-021)

**Scope**: Pure YAML additions + tests. No scanner code changes.

**Files to modify**:
- `src/exray/plugins/github_actions/rules/gha_rules.yaml` — add GHA-008
- `src/exray/plugins/npm_lifecycle/rules/npm_rules.yaml` — add NPM-020, NPM-021

**Files to modify (tests)**:
- `tests/test_github_actions.py` — add 8 tests for GHA-008
- `tests/test_npm_lifecycle.py` — add 9 tests for NPM-020/021

**Acceptance criteria**:
- GHA-008 fires on `uses: third-party/action@v1`, does NOT fire on `uses: actions/checkout@v4` or SHA-pinned refs
- NPM-020 fires on `rm -rf ~/`, `shred`, does NOT fire on `rm -rf node_modules`
- NPM-021 fires on `fs.rmSync(os.homedir())`, does NOT fire on normal file ops
- Preinstall escalation works with new rules (existing logic, no changes needed)
- All 270+ existing tests still pass

**Validation**: After adding rules, run the full test suite. Verify zero regressions. Count new test total.

**Commit**: `feat(rules): add unpinned action refs, destructive commands (GHA-008, NPM-020, NPM-021)`

### Step 2: GHA-008 Regex Validation

**Scope**: The unpinned action regex is the most complex pattern in this build. Validate it thoroughly.

**Task**: After adding GHA-008, create a temporary test script or add detailed test cases that exercise edge cases:
- `uses: some-org/some-action@v1.2.3` → should trigger
- `uses: some-org/some-action@abc1234` (7 chars) → judgment call: short SHAs are still mutable. Trigger.
- `uses: some-org/some-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2` (40 chars) → should NOT trigger
- `uses: docker://ghcr.io/some/image:latest` → should NOT trigger (docker ref, not action)
- `uses: actions/checkout@v4` → should NOT trigger (first-party)
- `uses: github/codeql-action/upload-sarif@v3` → should NOT trigger (first-party)

**If the regex is unreliable**: Fall back to programmatic detection in `scanner.py`. Parse the workflow text line-by-line, extract `uses:` directives, split on `@`, check if the ref portion is a 40-char hex string. This is more maintainable than a complex regex. Budget: ~25 lines in scanner.py.

**Commit**: amend the Step 1 commit if regex works, or `fix(gha-plugin): replace GHA-008 regex with programmatic check` if not

### Step 3: VS Code Scanner Refactor

**Scope**: Bring `scanner.py` under control before adding new logic.

**Current state**: 482 LOC (exceeds 300 LOC limit from CLAUDE.md).

**Refactoring targets**:
- The entropy check, base64 check, and obfuscation check are duplicated per-task in `_scan_single_task()`. These are the same checks that exist in the npm scanner. Extract them into a shared helper in `static_analysis.py` (e.g., `run_dynamic_checks(text, file_path, plugin_name, threshold) -> list[Finding]`).
- The line-number pinning logic may have duplication — consolidate if possible.
- Target: scanner.py under 450 LOC after refactor (strict 300 is aspirational given the JSON parsing complexity, but bring it down meaningfully).

**Acceptance criteria**:
- All 16 existing vscode tests pass without modification
- All 270+ tests pass
- scanner.py is measurably shorter
- No behavioral changes — pure refactor

**Commit**: `refactor(vscode-plugin): extract dynamic checks to reduce scanner LOC`

### Step 4: File Extension Mismatch Detection (VSC-007)

**Scope**: Add programmatic detection to vscode-tasks scanner + YAML rule entry + tests.

**Files to modify**:
- `src/exray/plugins/vscode_tasks/scanner.py` — add `_check_node_extension_mismatch()` method + call site
- `src/exray/plugins/vscode_tasks/rules/vscode_rules.yaml` — add VSC-007 entry (programmatic marker)

**Files to modify (tests)**:
- `tests/test_vscode_tasks.py` — add 11 tests per DEC-P3-003

**Acceptance criteria**:
- `node public/fonts/fa-brands-regular.woff2` → CRITICAL finding (VSC-007)
- `node ./scripts/setup.js` → no finding
- `node app.mjs` / `node index.ts` → no finding
- Combined with `runOn: folderOpen` → both VSC-001 and VSC-007 fire
- All existing tests still pass

**Commit**: `feat(vscode-plugin): add file extension mismatch detection (VSC-007)`

### Step 5: Demo Repo Update + Full Validation

**Scope**: Update supply-chain-demo, run Ex-Ray against it, verify all new rules fire.

**Tasks**:
1. Add fake font file and task to demo repo
2. Add destructive command pattern to setup.js
3. Run `exray .` against the updated demo repo
4. Verify findings include: GHA-008 (if demo ci.yml has unpinned third-party actions), NPM-020/021, VSC-007
5. Run `exray . --format sarif` and verify new rules appear in SARIF output
6. Run full test suite one final time

**Acceptance criteria**:
- Ex-Ray detects all planted patterns in the demo repo
- SARIF output includes new rule IDs
- Total test count: 270 + ~28 new = ~298 tests
- Coverage remains above 90%

**Commit** (in supply-chain-demo repo): `feat: add fake font and destructive command demo patterns`

---

## Constraints

- **No new dependencies.** Everything uses stdlib + existing deps.
- **No new plugins.** All changes go into existing plugin directories.
- **No architecture changes.** Models, plugin interface, orchestrator, CLI, reporting — all unchanged.
- **No network calls added.** GHA-008 is static pattern matching, not runtime tag verification.
- **Plugin LOC limits.** GHA scanner is at 117 (plenty of room). NPM scanner is at 445 (tight but adding YAML rules doesn't change scanner LOC). VSCode scanner is at 482 (needs refactor before adding code — see Step 3).
- **< 1% false positive standard** applies to all new rules. Test against known-good patterns to verify.

---

## What NOT to Build

- **No GitHub API integration** for action tag verification. GH audit logs and SIEM rules handle this. Ex-Ray stays offline/static.
- **No registry-level package scanning.** That's a future architectural extension, not a rule addition.
- **No typosquatting detection.** Deferred to a future phase per existing roadmap.
- **No Dockerfile scanning plugin.** Future phase.
- **No changes to the GitHub Action repo** (`ex-ray-action`). The new rules are picked up automatically when the action rebuilds its Docker image from the scanner repo.

---

## Success Criteria

This build is complete when:

- [ ] GHA-008 detects unpinned third-party Action references, excludes first-party and SHA-pinned refs
- [ ] NPM-020 detects destructive filesystem commands targeting home/root directories
- [ ] NPM-021 detects home directory targeting via JS APIs
- [ ] VSC-007 detects Node.js executing non-JavaScript file extensions
- [ ] VSCode scanner LOC is reduced from 482 via refactor
- [ ] All new rules have comprehensive positive AND negative test cases
- [ ] All existing 270 tests pass (zero regressions)
- [ ] New test count: ~298 total
- [ ] Coverage remains ≥ 90%
- [ ] Demo repo updated with new patterns
- [ ] Ex-Ray produces correct findings when run against updated demo repo