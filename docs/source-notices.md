# Offline component notices

From an existing distribution checkout with locally available pinned component
Git objects, run on Windows or Ubuntu:

```text
python vardrsec.py source-notices --destination ../component-notices
```

Use your Python 3.10+ launcher (`python3` where appropriate). The destination must
be new, its parent must exist, and it must be outside all input repositories.
Defaults read `.sources/map`, `.sources/runner` and `.sources/gate`. To use other
existing local repositories, pass `--map-repo PATH`, `--runner-repo PATH` and
`--gate-repo PATH`. Missing objects cause refusal; this command never fetches,
checks out sources, builds images or reads installation credentials. Acquire
sources separately through the existing installation/source workflow.

The collector reads `versions.json` from the distribution's committed `HEAD`,
then copies top-level `LICENSE`, `LICENCE`, `NOTICE`, `COPYING` and `COPYRIGHT`
files (including suffixed variants) from those exact component commits and the
distribution commit. It ignores modified/untracked worktree files. The output
contains those verbatim Git blobs, the committed `versions.json`, and a
`manifest.json` recording commits, trees, blob IDs, byte lengths, SHA-256 hashes
and GitHub source references. The command prints the manifest SHA-256. Existing
output is never overwritten. An I/O failure may leave partial output; the
manifest is written last. Retain it for diagnosis and choose a new destination.

This is a component-notice collection aid, not a full source bundle, source
offer, license compatibility decision or legal compliance assertion. It does
not inventory transitive dependencies, bundled tools, base images or packages.
Git object hashes bind the collected bytes to the selected local objects; they
do not authenticate repository provenance. Review the
[release license inventory](release-license-inventory.md) and remaining
[release checklist](community-alpha-release.md) separately, and collect again
from the exact reviewed release candidate before artifact delivery.
