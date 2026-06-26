# rave/tools/

Operator-facing CLI tools for verifying MacCrab plugins independently of the catalog. Tools here are self-contained — no installation required beyond Python 3.9+ (already on every modern macOS).

## Available tools

### `maccrab-rave-canonical-hash`

Compute the canonical tree hash for a `.maccrabplugin` artifact per plan §3.7. Used to verify a plugin reproducibly built from declared source matches the catalog-pinned hash.

```bash
# Default — just print the hex hash
./maccrab-rave-canonical-hash /path/to/MyPlugin.maccrabplugin.zip

# Verbose — per-file hashes on stderr, summary hash on stdout
./maccrab-rave-canonical-hash --verbose /path/to/MyPlugin.maccrabplugin.zip

# JSON output for scripts
./maccrab-rave-canonical-hash --json /path/to/MyPlugin.maccrabplugin.zip
```

The Mach-O normalization recipe is documented in the tool's docstring. Briefly: code signatures stripped via `codesign --remove-signature`, debug symbol references stripped via `strip -S`, embedded UUIDs handled because both `codesign` and `strip` rewrite them as a side effect.

### Future tools (not yet built)

- `maccrab-rave-verify`: end-to-end verification — download from author Release, verify Sigstore signature against catalog's `exact_signer`, fetch source, rebuild, compare canonical hashes
- `maccrab-rave-mirror`: pull catalog + author Release artifacts to local disk for air-gapped operator infrastructure per plan §3.9
- `maccrab-rave-revocation-check`: refresh `revocations.json` and report any locally-installed revoked versions

## Why CLI tools and not a library

Operators verify their plugins from the shell, not from inside MacCrab. CLI tools are scriptable, composable, and don't require the operator to trust MacCrab itself for the verification — the whole point of independent verification.

## Source

The canonical hash logic was developed and validated in `rave-prototypes/prototype-reproducible-plugin/scripts/canonical-hash.py`. The CLI here is the polished version with `--json` and proper `argparse` help. Both should produce identical hashes for the same input.
