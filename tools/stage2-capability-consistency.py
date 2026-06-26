#!/usr/bin/env python3
"""
Stage 2 — capability consistency (heuristic).

Walks a plugin source tree and checks whether what the source actually does
matches what the manifest declares. This is a HEURISTIC layer (per plan
§4.4 + §10): obvious violations fail the stage; the runtime broker is the
actual enforcement layer. Uncertain cases produce warnings that surface
for manual review.

Checks performed:

  1. URL endpoints in source vs manifest.capabilities.endpoints
  2. Process / posix_spawn / NSTask call sites vs manifest.capabilities.subprocesses
  3. SPDX license header presence on .swift files
  4. Hardcoded URLs pointing at author-controlled download domains (anti-pattern)
  5. Common secret patterns (Gitleaks-style regex; not a replacement for Gitleaks)

Usage:
    stage2-capability-consistency.py <plugin-source-tree>

Exits 0 if no FAILs (warns are OK). Exits 1 if any FAIL.
Always emits a JSON report on stdout for the CI workflow to render in the
job summary.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

__version__ = "0.1.0-prototype"


@dataclass
class Finding:
    severity: str  # "fail" or "warn"
    check: str
    file: str
    line: int
    detail: str


URL_PATTERN = re.compile(r'''https?://([a-z0-9.-]+)''', re.IGNORECASE)
PROCESS_RUN_PATTERN = re.compile(r'''\.executableURL\s*=\s*URL\(fileURLWithPath:\s*"([^"]+)"''')
POSIX_SPAWN_PATTERN = re.compile(r'''posix_spawn\([^,]+,\s*"([^"]+)"''')
NSTASK_PATTERN = re.compile(r'''Process\(\)''')  # weak signal; flags for review

# Crude secret patterns (subset of what Gitleaks covers; this is a fallback
# when Gitleaks isn't installed in the CI environment).
SECRET_PATTERNS = [
    (re.compile(r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PRIVATE)\s+(PRIVATE\s+)?KEY-----'), "private key"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS access key id"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GitHub personal access token"),
    (re.compile(r'gho_[A-Za-z0-9]{36}'), "GitHub OAuth token"),
    (re.compile(r'sk-[A-Za-z0-9]{32,}'), "OpenAI / similar API key"),
    (re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,}'), "Slack token"),
]

# A plugin's own author-controlled domains. Hardcoded download URLs to these
# domains are anti-pattern (sidesteps Sigstore + reproducibility).
SUSPICIOUS_DOWNLOAD_HOSTS = re.compile(
    r'\.(s3|cdn|storage|releases?|downloads?)\.', re.IGNORECASE
)


def load_manifest(source: Path) -> dict[str, Any]:
    candidates = list(source.rglob("manifest.json"))
    if not candidates:
        return {}
    # Prefer Contents/Resources/manifest.json (the bundle one)
    for path in candidates:
        if "Contents/Resources" in str(path):
            return json.loads(path.read_text())
    return json.loads(candidates[0].read_text())


def swift_sources(source: Path) -> list[Path]:
    out = []
    for path in source.rglob("*.swift"):
        # Skip Tests/, scripts/, .build/ generated files
        parts = path.parts
        if any(p in parts for p in (".build", ".swiftpm", "Tests", "tests")):
            continue
        out.append(path)
    return out


def check_url_endpoints(swift_files: list[Path], manifest: dict[str, Any]) -> list[Finding]:
    declared_hosts = {ep["host"] for ep in manifest.get("capabilities", {}).get("endpoints", [])}
    findings: list[Finding] = []
    for path in swift_files:
        for lineno, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
            for match in URL_PATTERN.finditer(line):
                host = match.group(1).lower()
                if host in declared_hosts:
                    continue
                # Common "ignore" cases — examples in docstrings, etc.
                stripped = line.lstrip()
                if stripped.startswith(("//", "*", "///")):
                    continue
                # Suspicious-host check is harder than declared/undeclared
                severity = "warn"
                detail = f"URL host '{host}' not in manifest.endpoints"
                if SUSPICIOUS_DOWNLOAD_HOSTS.search(host):
                    severity = "fail"
                    detail += " (author-controlled-download pattern — anti-pattern)"
                findings.append(Finding(
                    severity=severity, check="url-endpoint",
                    file=str(path.relative_to(path.parts[0]) if path.is_absolute() else path),
                    line=lineno, detail=detail,
                ))
    return findings


def check_subprocess_calls(swift_files: list[Path], manifest: dict[str, Any]) -> list[Finding]:
    declared_execs = {sp["executable"] for sp in manifest.get("capabilities", {}).get("subprocesses", [])}
    findings: list[Finding] = []
    for path in swift_files:
        text = path.read_text(errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            # executableURL = URL(fileURLWithPath: "/usr/bin/X")
            for match in PROCESS_RUN_PATTERN.finditer(line):
                exe = match.group(1)
                if exe not in declared_execs:
                    findings.append(Finding(
                        severity="fail", check="subprocess-call",
                        file=str(path), line=lineno,
                        detail=f"Process.executableURL targets '{exe}' not in manifest.subprocesses",
                    ))
            for match in POSIX_SPAWN_PATTERN.finditer(line):
                exe = match.group(1)
                if exe not in declared_execs:
                    findings.append(Finding(
                        severity="fail", check="subprocess-call",
                        file=str(path), line=lineno,
                        detail=f"posix_spawn targets '{exe}' not in manifest.subprocesses",
                    ))
            if NSTASK_PATTERN.search(line) and not declared_execs:
                findings.append(Finding(
                    severity="warn", check="subprocess-call",
                    file=str(path), line=lineno,
                    detail="Process() instance constructed; manifest declares no subprocess capabilities — review needed",
                ))
    return findings


def check_spdx_headers(swift_files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    spdx_re = re.compile(r'SPDX-License-Identifier:\s*\S+')
    for path in swift_files:
        head = "\n".join(path.read_text(errors="replace").splitlines()[:10])
        if not spdx_re.search(head):
            findings.append(Finding(
                severity="warn", check="spdx-header",
                file=str(path), line=1,
                detail="no SPDX-License-Identifier in top 10 lines",
            ))
    return findings


def check_secrets(source: Path) -> list[Finding]:
    findings: list[Finding] = []
    # Walk all text-y files including non-Swift (config, docs, scripts)
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        if any(p in path.parts for p in (".build", ".swiftpm", ".git", "dist")):
            continue
        if path.stat().st_size > 1_000_000:  # skip giant blobs
            continue
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, label in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        severity="fail", check="secret",
                        file=str(path), line=lineno,
                        detail=f"matched {label} pattern",
                    ))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="plugin source tree to analyze")
    parser.add_argument("--json", action="store_true", help="emit JSON only (no human prose)")
    args = parser.parse_args()

    if not args.source.is_dir():
        print(f"error: source path is not a directory: {args.source}", file=sys.stderr)
        sys.exit(2)

    manifest = load_manifest(args.source)
    if not manifest:
        print("error: no manifest.json found in source tree", file=sys.stderr)
        sys.exit(2)

    sources = swift_sources(args.source)
    findings: list[Finding] = []
    findings += check_url_endpoints(sources, manifest)
    findings += check_subprocess_calls(sources, manifest)
    findings += check_spdx_headers(sources)
    findings += check_secrets(args.source)

    fails = [f for f in findings if f.severity == "fail"]
    warns = [f for f in findings if f.severity == "warn"]

    report = {
        "tool": "stage2-capability-consistency",
        "version": __version__,
        "plugin_id": manifest.get("id"),
        "swift_files_scanned": len(sources),
        "fail_count": len(fails),
        "warn_count": len(warns),
        "findings": [asdict(f) for f in findings],
    }

    print(json.dumps(report, indent=2))

    if not args.json:
        # Also a human one-liner on stderr for tail-friendly logs
        verdict = "FAIL" if fails else ("PASS-WITH-WARNS" if warns else "PASS")
        print(f"stage2: {verdict} ({len(fails)} fail, {len(warns)} warn, {len(sources)} swift files)",
              file=sys.stderr)

    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
