# Ex-Ray

Static analysis scanner for detecting malicious patterns in developer tooling configurations.

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Ex-Ray targets the "developer autopilot" attack surface — npm lifecycle scripts, VS Code tasks, and GitHub Actions workflows that execute silently without scrutiny. It detects patterns used in real campaigns like Contagious Interview and Shai Hulud.

---

## Installation

```bash
git clone https://github.com/ymlsurgeon/ex-ray.git
cd ex-ray
pip install -e .
```

**Requirements**: Python 3.10+

---

## Usage

```bash
# Scan a directory
exray /path/to/project

# Output formats
exray . --format text    # default, color terminal output
exray . --format json    # machine-readable
exray . --format sarif   # SARIF 2.1.0 for GitHub/GitLab integration

# Run specific plugins
exray . --plugin npm-lifecycle
exray . --plugin vscode-tasks

# CI/CD — webhook delivery and tenant tagging
exray . --format sarif --webhook-url https://collector.example.com/token
exray . --format sarif --tenant-id acme-corp --webhook-url https://...

# List available plugins
exray --list-plugins
```

**Exit codes**: `0` = clean, `1` = findings detected, `2` = scan error

---

## Detection Coverage

| Plugin | Files Scanned | Rules |
|--------|--------------|-------|
| `npm-lifecycle` | `package.json`, referenced `.js` files | eval/exec, base64, network calls, env exfiltration, obfuscation, entropy |
| `vscode-tasks` | `.vscode/tasks.json` | auto-execution (`runOn: folderOpen`), shell injection, hidden tasks, network access |
| `github-actions` | `.github/workflows/*.yml` | workflow injection, runner abuse, secret exfiltration |

---

## CI/CD Integration

```yaml
# GitHub Actions
- name: Run Ex-Ray
  run: |
    pip install git+https://github.com/ymlsurgeon/ex-ray.git
    exray . --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

See `CLAUDE.md` for development workflow and coding standards.

---

## License

MIT — see [LICENSE](LICENSE) for details.
