# CLAUDE.md — Workflow Protocols for Ex-Ray

> **Read this file before every session.** This defines how you should behave during development — when to proceed, when to stop, and how to handle problems.
> **Read `.claude/decisions.md` before writing any code.** That file defines what we're building and why.

---

## North Security Star

This is a sole principal for building out this tool and ensuring it's safe and secure. During the build process of this tool you will ensure that all tradtional security coding standards are met. This includes but is not limited to:

- Sanitize inputs to prevent SQL injection and XSS
- Use parameterized queries for database interaction if applicable
- Handle errors gracefully without exposing stack traces
- Use established, secure cryptographic libraries and protocols; avoid custom encryption algorithms if applicable

### **CRITICAL: Package Installation Safety**

**NEVER install NPM packages on this machine under ANY circumstances**, including:

- ❌ **NO `npm install`** - Not for malicious samples, not for known-good packages, not for testing
- ❌ **NO `npm ci`** - Never install from package-lock.json
- ❌ **NO lifecycle script execution** - postinstall, preinstall, etc. must never run
- ✅ **ONLY use `npm pack`** - Downloads tarball without executing any code
- ✅ **ONLY static analysis** - Extract tarballs, read files, analyze content
- ✅ **Test fixtures only** - All tests use pre-created fixtures in `tests/fixtures/`

**Rationale**: This is a malware analysis tool. Installing packages would execute malicious code (postinstall scripts, etc.) and compromise the development machine. All analysis must be static only.


## Core Principles

1. **Never guess on security-sensitive decisions.** This is a security tool. If you're unsure whether a detection pattern is correct, a rule is too broad, or a design choice has security implications — stop and ask.
2. **Follow the implementation order.** `decisions.md` defines Steps 1-10 in a specific sequence. Do not skip ahead or parallelize unless explicitly told to.
3. **Small, working increments.** Each step should end with passing tests. Do not move to the next step with broken tests from the current step.
4. **When in doubt, ask. When confident, proceed.**

---

## When to STOP and Ask for Human Input

### Always stop for:

- **Architecture changes**: Any deviation from the structure in `decisions.md` — new modules, different class hierarchies, changed plugin interface contracts
- **New dependencies**: Do not add any dependency not listed in DEC-010 without approval. If you think one is needed, explain why and suggest it — don't install it
- **Model schema changes**: Any modification to `Finding`, `Rule`, `ScanResult`, or `Severity` beyond what's specified in DEC-002
- **Detection logic ambiguity**: If a rule could produce excessive false positives or miss obvious true positives, flag the tradeoff before implementing
- **Scope creep**: If you notice an opportunity to add something cool that isn't in the MVP scope — note it but don't build it. Add a placeholder comment or a future decision entry instead
- **Security concerns**: If you spot a vulnerability in the design, a way the tool could be abused, or a pattern that doesn't feel right — raise it immediately

### Proceed without asking for:

- Implementing exactly what `decisions.md` specifies
- Writing tests for implemented functionality
- Fixing linting issues, type errors, or import problems
- Adding docstrings and type hints
- Refactoring within a module to stay under LOC limits
- Creating fixtures and test data
- Bug fixes that don't change the interface

---

## Error Handling During Build

### Tests fail

1. Read the error message carefully
2. If it's a straightforward bug (typo, wrong import, logic error) — fix it and re-run
3. If tests fail because the design doesn't work as expected — stop. Explain what went wrong, what you think the fix is, and wait for approval before changing the design
4. Never delete or skip a failing test to move forward

### Dependency issues

1. If `pip install -e .` fails — check `pyproject.toml` syntax first
2. If a listed dependency has a breaking change or conflict — report it with the exact error. Do not substitute an alternative dependency without approval
3. If a dev dependency (pytest, etc.) has issues — you can troubleshoot independently

### Ambiguous requirements

1. Check `decisions.md` first — the answer is probably there
2. If it's genuinely unclear, present your interpretation along with alternatives: "I read this as X, but it could also mean Y. I'll proceed with X unless you say otherwise."
3. For anything involving detection logic or rule design — always ask rather than assume

### Something feels wrong

If the architecture from `decisions.md` doesn't fit once you start implementing — say so. Explain the friction, propose an alternative, and wait. Do not silently deviate.

---

## Commit and Checkpoint Conventions

### When to commit

- After completing each implementation step (Steps 1-10)
- After a meaningful sub-milestone within a step (e.g., rules written but scanner not yet wired up)
- Before starting any refactoring

### Commit message format

```
type(scope): short description

[optional body with context]
```

**Types**: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`
**Scopes**: `core`, `npm-plugin`, `vscode-plugin`, `cli`, `docs`

**Examples:**
```
feat(core): implement Finding and Rule pydantic models
test(core): add serialization tests for all models
feat(npm-plugin): implement lifecycle script detection rules
fix(npm-plugin): handle malformed package.json without crashing
docs: update decisions.md with DEC-011 git hooks design
```

### Checkpoint summaries

After completing each step, provide a brief summary:
- What was implemented
- What tests pass
- Any concerns, tradeoffs, or deviations noted
- Ready for next step: yes/no

---

## Things You Must NOT Do

- **Do not install NPM packages.** NEVER run `npm install`, `npm ci`, or any command that executes package code. Use `npm pack` only.
- **Do not add network calls.** This tool is offline-only. No fetching, no phoning home, no update checks.
- **Do not use `print()`.** Use `logging` or `rich.console`.
- **Do not use `Any` type hints** unless there is a concrete, documented reason.
- **Do not create god classes.** If a class is doing more than one thing, split it.
- **Do not write plugins longer than 300 lines.** Move shared logic to `static_analysis.py`.
- **Do not change the plugin interface** (`scan`, `get_metadata`, `get_supported_files`) without approval.
- **Do not auto-generate rules.** Every detection rule must be intentional and documented with a rationale.
- **Do not silence exceptions.** Catch them, log them, and include them in scan results per DEC-009.
- **Do not refactor decisions.md** unless explicitly asked to.

---

## Code Quality Checks Before Each Checkpoint

Run these before reporting a step as complete:

```bash
# All tests pass
pytest tests/ -v

# No type errors (if mypy is configured)
mypy src/exray/

# Check plugin LOC limits
wc -l src/exray/plugins/*/scanner.py
# Each should be < 300 lines

# Verify editable install works
pip install -e . && exray --help
```

---

## How to Handle Tradeoffs

When you encounter a tradeoff (detection coverage vs. false positive rate, simplicity vs. extensibility, etc.):

1. **Name the tradeoff explicitly.** "This rule catches X but will also flag Y."
2. **State your recommendation.** "I'd lean toward broader detection because false positives are cheaper than missed malware."
3. **Wait for a decision** if it affects rule design or architecture. Proceed if it's a pure implementation detail.

Document significant tradeoffs as comments in the code:

```python
# TRADEOFF: This entropy threshold (4.5) catches most base64 but also flags
# legitimate long strings like URLs. Tuned for security-first, may need adjustment.
ENTROPY_THRESHOLD = 4.5
```

---

## Session Startup Checklist

At the start of every coding session:

1. Read this file (`CLAUDE.md`)
2. Read `decisions.md`
3. Check which implementation step we're on
4. Review any open concerns from the last session
5. Confirm the plan before writing code: "Starting Step N — here's what I'll build..."

---

## Communication Style

- Be direct. Say "this won't work because X" not "there might potentially be a slight concern."
- When reporting progress, lead with status: ✅ done, ⚠️ concern, ❌ blocked.
- If something is going to take significantly more code than expected, flag it early.
- Don't over-explain things I already know. I'm a security analyst — you can be technical.

---

*Last updated: 2025-02-07*
*Status: Pre-build — scaffolding phase*
