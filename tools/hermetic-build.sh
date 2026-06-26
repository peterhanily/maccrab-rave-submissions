#!/usr/bin/env bash
# hermetic-build.sh — build a contrib plugin from source with a RECORDED toolchain,
# PINNED dependencies, and NO network egress, so a malicious or careless build
# script cannot fetch code at build time and SwiftPM cannot pull an unpinned /
# unvetted transitive dependency. Stage 3 of the vetting pipeline (plan §4.4, §10).
#
# Three layers:
#   1. toolchain record — CI pins DEVELOPER_DIR (the Xcode/Swift toolchain); we
#      RECORD the exact versions. The canonical reproducibility hash is only
#      comparable across the same toolchain, so an unpinned toolchain silently
#      breaks reproducibility — recording it makes a drift visible.
#   2. dependency pin — if Package.swift declares dependencies, a committed
#      Package.resolved MUST be present (the vetted, pinned graph) or we fail
#      closed. Deps are fetched in a NETWORK phase BEFORE the sandbox, which
#      populates SwiftPM's global repository cache; the build itself is offline
#      and clones from that cache.
#   3. egress denial — the author build (scripts/package-plugin.sh) runs under
#      sandbox-exec with `(deny network*)` — macOS Seatbelt, the same containment
#      tech the app uses for Tier B. Any build-time network access fails the build.
#
# BUILD-SCRIPT CONTRACT: we export MACCRAB_HERMETIC=1 and run the build inside a
# Seatbelt sandbox. SwiftPM normally wraps manifest evaluation in ITS OWN Seatbelt
# sandbox, and macOS forbids a nested sandbox_apply — so a build script that runs
# a bare `swift build` dies with "sandbox_apply: Operation not permitted" inside
# ours. A conforming script (see the reference plugin template) therefore passes
# `swift build --disable-sandbox` when MACCRAB_HERMETIC=1 — our outer sandbox is
# strictly tighter (it denies ALL network), so SwiftPM's inner one is redundant.
# A non-conforming script fails closed here, which is the safe direction.
#
# LIMITATIONS (honest): on a hosted GitHub macOS runner this is the strongest
# egress restriction available without a custom image. Seatbelt is process-scoped,
# not a VM: it denies network operations but does NOT restrict filesystem reads,
# and a kernel-level sandbox escape would bypass it. Capability binding (Stage 2)
# and the reproducibility canonical hash (Stage 3) are the complementary layers.
# A true per-build hermetic VM needs ephemeral / self-hosted runners.
#
# Usage: hermetic-build.sh <source-dir>
#   FAIL-CLOSED: any missing prerequisite or build failure exits non-zero so the
#   vetting-gate stays un-green and the submission cannot merge.
set -euo pipefail

SRC="${1:?usage: hermetic-build.sh <source-dir>}"
cd "$SRC"

echo "==> toolchain"
echo "    DEVELOPER_DIR=${DEVELOPER_DIR:-(default)}"
if ! swift --version 2>&1 | sed 's/^/    /'; then
  echo "::error::swift toolchain not found"; exit 1
fi

BUILD_SCRIPT="scripts/package-plugin.sh"
if [[ ! -x "$BUILD_SCRIPT" ]]; then
  echo "::error::missing executable $BUILD_SCRIPT — non-standard build layout"
  exit 1
fi

# --- dependency pin (network phase, BEFORE the sandbox) -----------------------
# A package with no `.package(` dependency declarations needs no Package.resolved
# (e.g. the reference plugin is dependency-free). One WITH declared dependencies
# must commit Package.resolved so the graph is pinned + vettable.
if [[ -f Package.swift ]] && grep -Eq '\.package[[:space:]]*\(' Package.swift; then
  if [[ ! -f Package.resolved ]]; then
    echo "::error::Package.swift declares dependencies but no Package.resolved is committed — an unpinned dependency graph is not vettable"
    exit 1
  fi
  echo "==> resolving pinned dependencies (network phase; populates the SwiftPM cache)"
  # --disable-automatic-resolution: error rather than silently re-pin when the
  # committed Package.resolved is stale against Package.swift.
  if ! swift package resolve --disable-automatic-resolution; then
    echo "::error::committed Package.resolved is stale or unresolvable against Package.swift"
    exit 1
  fi
else
  echo "==> no external dependencies declared (nothing to resolve)"
fi

# --- hermetic build (no egress) ----------------------------------------------
# allow default = let the compiler read SDKs / spawn clang+ld / write build output;
# deny network* = block every network operation (outbound, inbound, bind, DNS).
# MACCRAB_HERMETIC=1 signals the build script to pass `swift build --disable-sandbox`
# so SwiftPM does not try to nest its own (now-redundant) Seatbelt sandbox in ours.
export MACCRAB_HERMETIC=1
SANDBOX_PROFILE='(version 1)(allow default)(deny network*)'
if command -v sandbox-exec >/dev/null 2>&1; then
  echo "==> building under Seatbelt no-network sandbox"
  sandbox-exec -p "$SANDBOX_PROFILE" "./$BUILD_SCRIPT"
else
  # Non-macOS / local dev without Seatbelt: the build still runs, but WITHOUT
  # egress isolation. CI is macos-14 (Seatbelt present), so this branch never
  # weakens CI — it only keeps the tool usable off-macOS.
  echo "::warning::sandbox-exec unavailable — building WITHOUT egress isolation (expected only off-macOS)"
  "./$BUILD_SCRIPT"
fi
echo "==> hermetic build complete"
