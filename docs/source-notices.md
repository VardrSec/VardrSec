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

## Full web source attribution

The standard Full build supplies the Map source revision to the web image only
when its resolved build context is the clean, pinned managed checkout, including
the absence of ignored local build inputs. Custom contexts, alternate Dockerfiles
and unverifiable checkouts receive no exact-revision attribution. Map versions
that support the source link then identify the repository instead. This metadata
does not establish reproducible builds or complete corresponding-source delivery.
Mapless does not build or attribute a Map web image.

## Runtime license locations

The proxy retains Caddy's license and available upstream notice at
`/usr/share/licenses/caddy/`. The database retains gosu's equivalent files at
`/usr/share/licenses/gosu/`. The proxy also retains the distribution wrapper's
unchanged license and notice at `/usr/share/licenses/vardrsec/`. These copies accompany the rebuilt binaries; they
do not replace dependency notices or complete corresponding-source delivery.

Each rebuilt Caddy/gosu notice directory also includes `GO-LICENSE` and
`dependency-notices.tar.gz`, preserving legal text paths from that builder's
Go module cache. The compressed archive is inert data and is not extracted by
the service. It may include unlinked cached modules; it does not establish
license compatibility, exhaustive notice coverage or complete corresponding
source. Compiler and binary build commands are unchanged.

## Database libxml2 source

The database image rebuilds its existing Debian libxml2 version with the
maintained Ubuntu entity, dictionary, validation, XPointer, output and XInclude
security backports. PostgreSQL's version and configuration
are unchanged. The build checks the Debian source descriptor, both source
archives and every patch against fixed SHA-256 values before unpacking or building.
Build tools remain in a discarded stage.

`/usr/share/doc/libxml2/vardr-source/` contains the original source archive,
modified Debian source archive and descriptor, patch, build recipe, provenance,
build metadata and `SHA256SUMS`. Existing Debian copyright/common-license files
remain installed. To export just these sources from a checkout:

```text
docker build --target libxml2-source-delivery --output type=local,dest=../libxml2-source -f db/Dockerfile db
```

Choose a new destination outside the checkout. This source delivery covers the
modified library; it does not establish complete source delivery for every image
package. A custom package suffix does not itself clear vulnerability findings;
version-based scanners may require separate review of the retained patch evidence.

## Proxy go-jose v3 source backport

The proxy keeps its existing Caddy release and go-jose v3 API. A hash-pinned
source patch adapts upstream's RSA parameter checks and rejection of private
embedded header keys. As in the maintained upstream fix, RSA JWK moduli above
4096 bits are refused by default. Ordinary public keys and explicitly parsed
private JWKs remain supported; this is not a blanket PEM/TLS key-size limit.

`/usr/share/licenses/caddy/go-jose-v3/` contains the original checksum-verified
v3.0.5 source ZIP, patched source archive, patch, Apache license, source identity,
wrapper module graph, binary build information, build recipe and `SHA256SUMS`.
These are inert source/notice files. The Go build information explicitly records
the local module replacement; it is not an upstream patched v3 release. No CVE
ignore or scanner exception is applied. Missing version metadata for a local
replacement is not proof of vulnerability clearance; retain its source evidence
when reviewing the final image.
