#!/usr/bin/env python3
"""
Stage 2 — capability consistency (enforcing; source-side checks heuristic).

Walks a plugin source tree and checks whether what the source actually does
matches what the manifest declares. This is a HEURISTIC layer (per plan
§4.4 + §10): obvious violations fail the stage; the runtime broker is the
actual enforcement layer. Uncertain cases produce warnings that surface
for manual review.

Checks performed:

  1. URL endpoints in source vs manifest.networkConnectAllowlist
  2. Process / posix_spawn / NSTask call sites vs manifest.processExecPaths
  3. SPDX license header presence on .swift files
  4. Hardcoded URLs pointing at author-controlled download domains (anti-pattern)
  5. Common secret patterns (Gitleaks-style regex; not a replacement for Gitleaks)
  6. (with --entry) catalog privacy_class <-> requires_encrypted_scan coupling:
     a sensitive class (personal-comms / content) MUST carry the encrypted-scan
     flag. /api/submit synthesizes this, but a hand-edited catalog PR could ship
     `content` with the flag off and have the app treat it as plaintext-scannable.

The source-vs-manifest checks (1, 2, 4) are heuristic (regex over .swift); the
manifest/catalog coupling check (6) is exact. A declared capability that the
source actually exercises but the manifest omits is a FAIL — so the manifest is
the binding contract, not advisory.

Usage:
    stage2-capability-consistency.py <plugin-source-tree> [--entry catalog/<id>.json]

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

__version__ = "1.0.0"


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
    # Flat v1 manifest: networkConnectAllowlist is a list of allowed hosts (host or
    # host:port). (Was reading the nested v0 capabilities.endpoints, which never
    # exists in v1 — so the declared set was always empty and every URL false-flagged.)
    declared_hosts = {str(h).split(":")[0].lower() for h in manifest.get("networkConnectAllowlist", [])}
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
                detail = f"URL host '{host}' not in manifest.networkConnectAllowlist"
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
    # Flat v1 manifest: processExecPaths is a list of allowed absolute exec paths.
    # (Was reading nested v0 capabilities.subprocesses, always empty in v1 — so a
    # plugin that legitimately declared its execs was still failed, and the
    # declared/undeclared distinction never actually bound to the manifest.)
    declared_execs = set(manifest.get("processExecPaths", []))
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
                        detail=f"Process.executableURL targets '{exe}' not in manifest.processExecPaths",
                    ))
            for match in POSIX_SPAWN_PATTERN.finditer(line):
                exe = match.group(1)
                if exe not in declared_execs:
                    findings.append(Finding(
                        severity="fail", check="subprocess-call",
                        file=str(path), line=lineno,
                        detail=f"posix_spawn targets '{exe}' not in manifest.processExecPaths",
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


PRIVACY_CLASSES = ("metadata", "personal-comms", "content")


def check_privacy_coupling(entry: dict[str, Any]) -> list[Finding]:
    """Exact catalog-entry invariant: requires_encrypted_scan == (privacy_class != metadata).

    Mirrors the synthesis rule in api/_lib/submission.js so a hand-edited catalog PR
    (which never went through /api/submit) can't ship a sensitive class with the
    encrypted-scan opt-in disabled. entity is the catalog entry, not the manifest.
    """
    findings: list[Finding] = []
    pc = entry.get("privacy_class")
    if pc not in PRIVACY_CLASSES:
        findings.append(Finding(
            severity="fail", check="privacy-class",
            file="catalog-entry", line=0,
            detail=f"privacy_class {pc!r} is not one of {PRIVACY_CLASSES}",
        ))
        return findings
    expected = pc != "metadata"
    actual = bool(entry.get("requires_encrypted_scan", False))
    if actual != expected:
        findings.append(Finding(
            severity="fail", check="privacy-class",
            file="catalog-entry", line=0,
            detail=(f"requires_encrypted_scan={actual} contradicts privacy_class={pc!r} "
                    f"(expected {expected}); a {pc} plugin must "
                    f"{'require' if expected else 'not require'} encrypted-scan opt-in"),
        ))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="plugin source tree to analyze")
    parser.add_argument("--entry", type=Path, default=None,
                        help="catalog entry JSON for the privacy_class coupling check")
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
    if args.entry is not None:
        if not args.entry.is_file():
            print(f"error: --entry path is not a file: {args.entry}", file=sys.stderr)
            sys.exit(2)
        findings += check_privacy_coupling(json.loads(args.entry.read_text()))

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
