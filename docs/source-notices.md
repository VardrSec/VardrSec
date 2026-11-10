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
[release license inventory](release-license-inventory.md) and [support limits](limitations.md) separately, and collect again
from the exact reviewed release candidate before artifact delivery.

## Optional source archives

Add `--include-sources` to collect `COMPONENT/source.tar` for the distribution
and each pinned component. Each archive is streamed from the exact committed Git
tree, without checkout filters or untracked/modified files. Its manifest entry
records byte length, SHA-256, format, verified tracked-file count and a source
reference beside the existing commit and tree IDs. Notice-only output remains
the default.

These are standard Git archives, checked against every tracked Git blob before
the completed manifest is written. Missing, duplicate, altered or wrong-type
members refuse completion, as do changed executable bits. Committed or local
export attributes that omit a file therefore cause refusal rather than a
successful incomplete delivery. Tree-based archives do not substitute commit
metadata with `export-subst`.

Submodules and Git LFS pointers require separately delivered source and refuse
this archive mode; they are not silently represented as complete payloads.
Dependencies, generated files, external build inputs and tool/base-image sources
are not assembled.
Archives are not extracted by this command. This option therefore does not
establish complete corresponding source, reproducible builds or fulfillment of
source-delivery obligations. Review the archive and remaining delivery scope
before redistribution. Missing objects or archive failure leave no completed
manifest; retain partial output and use a new destination.
