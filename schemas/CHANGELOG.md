# Schema changelog

Schemas under `rave/schemas/` are versioned independently. Breaking changes bump the major; additive changes (new optional fields) bump the minor. Operators verify their installed-plugin compatibility by comparing the schema versions the catalog uses against what their `maccrabctl` was built with.

## v0 (2026-05-21) — first locked release

Promoted from v0-draft. All three schemas validate against JSON Schema Draft 2020-12. Source-of-truth: this directory.

### `manifest.json`

The shape MacCrab plugins put in their `.maccrabplugin` bundle at `Contents/Resources/manifest.json`.

- `id`, `version`, `name`, `description`, `min_maccrab_version`, `max_maccrab_version`, `min_macos`, `protocol_version`, `capabilities`, `mcp_tools`, `containment_relaxations`
- `protocol_version` is exactly `"0.0"` for plugins compatible with Brokered Access Protocol v0
- `description` capped at 400 chars to bound prompt-injection surface for `recommend_plugins` (plan §11 A8)
- `containment_relaxations` capped at 2 per plugin per plan §3.4 entitlement-relaxation policy gate
- `capabilities.files[].path` is exact-or-directory-prefix; glob patterns reserved for v0.1
- `capabilities.endpoints[].host` is exact hostname; wildcards reserved for v0.1

### `catalog-entry.json`

The shape of each `rave/catalog/<plugin-id>.json` file.

- Per-version pinned digests: `artifact_sha256` (transport), `canonical_tree_sha256` (source), `manifest_sha256`, `sigstore_bundle_sha256`, optional `slsa_attestation_sha256`
- Per-version `exact_signer` block records the specific Sigstore certificate identity observed at vetting (not just the channel-policy regex)
- `containment_layer_2_mechanism` (NEW in v0 per plan v4.4 §3.4 update): enum of `sandbox-exec-strict`, `sandbox-exec-permissive`, `none`. Default `sandbox-exec-strict`.
- `status` enum tracks plan §13.5 author-unreachable lifecycle: `active`, `unreachable_temporary`, `unreachable_extended`, `archived`, `revoked`

### `revocation.json`

The shape of `rave/revocations.json` — Sigstore-signed by the maccrab-rave project OIDC identity.

- Three revocation scopes: `single_version`, `version_range`, `all_versions`
- Seven `code` values: `compromise`, `supply_chain_incident`, `malicious_intent`, `critical_bug_user_impact`, `policy_violation`, `author_request`, `abuse_pattern`
- `decided_by` array enforces multi-signer revocations once governance §13.2 reaches multi-maintainer

## v1 (2026-05-24) — platform-aligned (per plan v4.5)

Substantive rewrite of `manifest.json` + `catalog-entry.json` to align with the platform's actual Tier B implementation at `peterhanily/maccrab:Sources/MacCrabForensics/TierB/`. Per plan v4.5 §3.2.

### `manifest.json` v1

Flattened to match `TierBManifest.swift`. Field changes from v0:

| v0 field | v1 status | Reason |
|---|---|---|
| `id` | unchanged | |
| `version` | unchanged | |
| `name` | renamed → `displayName` | matches `TierBManifest.displayName` |
| `description` | unchanged | |
| `min_maccrab_version`, `max_maccrab_version`, `min_macos` | DROPPED | belong in the catalog entry's `metadata` block, not the per-plugin manifest |
| `protocol_version` | DROPPED | MCP version negotiation lives in MCP layer; not the manifest |
| `capabilities` (nested object) | DROPPED | flattened to top-level fields below |
| `capabilities.files[]` (with `mode`) | split → `fileReadSubpaths[]` + `fileWriteSubpaths[]` | matches `TierBManifest.fileReadSubpaths` / `fileWriteSubpaths` (just subpath strings, no per-entry mode) |
| `capabilities.endpoints[]` | renamed → `networkConnectAllowlist[]` | matches platform; `host:port` strings (not nested `{host, ports[]}`) |
| `capabilities.subprocesses[]` | renamed → `processExecPaths[]` + `allowProcessFork` | matches platform's `SandboxProfileSpec` shape |
| `capabilities.metadata_namespaces[]` | DROPPED | MCP tool calls go via the MCP protocol directly; not pre-declared in the manifest |
| `mcp_tools[]` | DROPPED | MCP tools are discovered at runtime via `tools/list`; not pre-declared |
| `containment_relaxations[]` | DROPPED from manifest | moved to catalog-entry as `containment_relaxations` field (operator-visible audit trail, not author-controlled) |
| `schemaVersion` | NEW (const 1) | explicit version marker |
| `machServiceConnects[]` | NEW (matches platform) | mach service names for IPC |

### `catalog-entry.json` v1

Replaces Sigstore-specific fields with Ed25519. Field changes from v0:

| v0 field | v1 status | Reason |
|---|---|---|
| `signing_identity_pattern` | DROPPED | Sigstore-specific |
| `versions.<v>.exact_signer.*` (issuer, repository, workflow_ref, run_id, rekor_log_index, etc.) | DROPPED | Sigstore certificate identity fields; Ed25519 has no equivalent |
| `versions.<v>.sigstore_bundle_sha256` | DROPPED | no Sigstore bundle |
| `versions.<v>.slsa_attestation_sha256` | DROPPED | no SLSA attestation pinning |
| `signer_identity` | NEW (top-level) | Human-readable publisher identity for install-time UI |
| `signer_public_key_sha256` | NEW (top-level) | Trust handle — SHA-256 of publisher's Ed25519 public key |
| `versions.<v>.signature_sha256` | NEW | SHA-256 of the plugin's `signature` file |
| `runtime` | NEW (top-level) | enum `tierA`/`tierB`; matches platform's `PluginManifest.runtime` |
| `manifest_path` | narrowed `Resources/manifest.json` → `manifest.json` | flat-directory plugin format |

## v1.1 (2026-06 — trust-floor provenance keystone, additive)

Additive only — no field removed or narrowed, so every existing catalog entry/index/list keeps validating and old `maccrabctl` clients ignore the new fields. These fields are **required-going-forward** (emitted by `tools/regenerate-catalog` + `/api/admin/revoke.js`) but kept OUT of the schemas' `required` arrays so the pre-ceremony signed `catalog.json`/`revocations.json` still validate; they flip to `required` in the offline re-sign ceremony commit that lands the regenerated signed bytes. Field-presence on regenerated output is locked by `tests/catalog-schema-fields.test.js`.

### `catalog.json` (master index)

| Field | Where | Purpose |
|---|---|---|
| `schema_version` | top-level | Catalog-index format version (`"1"`). Bound into the client provenance receipt. |
| `catalog_serial` | top-level | **Signed monotonic** freshness counter (integer ≥ 0, prev+1 each regeneration). Client rejects a later validly-signed catalog with a lower `catalog_serial` as a stale-catalog replay/rollback. |
| `signer_public_key_sha256` | each `PluginSummary` | Surfaces the per-entry trust handle into the grid so a plugin can be key-pinned without a per-plugin round-trip. |

### `catalog-entry.json`

| Field | Purpose |
|---|---|
| `schema_version` | Per-entry format version (`"1"`), distinct from the master-index `catalog.schema_version`. |

`metadata.min_maccrab_version` / `max_maccrab_version` / `min_macos` confirmed sufficient as the client version floor/ceiling — no per-version floor field added (a plugin's compatibility floor is plugin-wide).

### `revocation.json`

| Field | Purpose |
|---|---|
| `serial` | **Signed monotonic** revocation-list serial (integer ≥ 0, +1 each change; never decreases). Client rejects a lower-serial validly-signed list as a stale/rollback replay that would silently un-revoke a compromised plugin. Distinct from `version` (the format version, still bare `"0"`). |

## v0.1 (not released)

Planned-but-not-released; superseded by v1's reshape. The planned v0.1 additions (glob path patterns, wildcard hostnames, kit_membership) would have been additive on v0; in v1 they become either:

- **Glob path patterns**: hold for v1.1; the platform's `SandboxProfileSpec` has subpaths only, no glob. Adding glob requires platform-side support too.
- **Wildcard hostnames**: hold for v1.1; same reasoning — `networkConnectAllowlist` is `host:port` strings; wildcards need platform-side support.
- **`kit_membership`**: still planned for v1.1; not blocked on platform changes.

## v0 (2026-05-21) — initial release (now superseded)

Promoted from v0-draft to v0 in Phase 0b-finalization; superseded by v1 per plan v4.5. See plan v4.4 + the rave/phase-0a branch's prior commits for the v0 shape and rationale.

## v0-draft

The initial Phase 0b-scaffolding schemas. Never deployed.

## Change control discipline

Schema PRs go through the standard rave-validate-submission pipeline. A schema bump that breaks any existing catalog entry fails CI. A backward-compatible additive change passes. Operators with an older `maccrabctl` continue to install plugins whose catalog entries use newer fields they don't know about; unknown fields are ignored at the client side.
