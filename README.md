# maccrab-rave-submissions

Public intake for **community plugin submissions** to [MacCrab Rave](https://rave.maccrab.com).

Submissions open PRs here (via the rave site's submit form), and the **vetting CI**
(reproducible build + Ed25519 signature + containment checks) runs on this repo's
**free public-repo Actions minutes** — keeping untrusted, attacker-supplied build
scripts off the private signing repo.

Nothing here is signed or trusted. The signed catalog lives in the private
`maccrab-rave` repo; only **owner-vetted** entries are promoted there and signed by
an offline key. `schemas/`, `tools/`, and `catalog/` are a periodically-refreshed
snapshot used by the vetting checks (collision + diff).
