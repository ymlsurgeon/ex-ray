# Mission

Build an open-source, extensible scanner that detects malicious patterns in developer tooling configurations. Focus on attack surfaces where developers execute code without scrutiny ("developer autopilot moments").

## Problem Space

Recent supply chain attacks exploit developer trust:

- **Shai Hulud (npm)**: Worm spreading via postinstall scripts, package.json manipulation
- **Contagious Interview (DPRK)**: VS Code tasks.json weaponization, auto-execution on project open

**Common theme**: Attackers abuse legitimate developer tool features to achieve persistence and exfiltration.

## Current Tooling Gaps

- **Socket.dev** covers npm (commercial, proprietary)
- No open-source tools for VS Code tasks, git hooks, or unified multi-vector scanning
- **Market opportunity**: Be the OSS alternative with broader attack surface coverage