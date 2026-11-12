# Changelog

## Unreleased

- Show a sanitized completed synthetic assessment, including independent write
  verification, retained report revisions and the limits of automated validation.

- Explain existing managed-worker status and recovery actions, distinguish
  assessment authorization from credentials, and connect policy review to evidence
  and a separately authorized retest. Clarify exact-image security evidence limits.
- Backport bounded RSA JWK parsing to the proxy's existing go-jose v3 API and
  retain original/patched source, build metadata and dependency notices.

## [0.1.0-dev.1] — source snapshot prepared

This version identifies the development source snapshot, not a published release.
The installation manifest remains development-only; no image release is declared.

- Clarify the separate Full and Mapless first-assessment paths and distinguish
  manual advisory checks from controlled execution requirements.

- Extend the database libxml2 backport with maintained dictionary, validation,
  XPointer, output and XInclude security fixes, retaining the patch sources.
- Select the reviewed Runner libpcap fix and Dalfox dependency notice/source
  delivery for both Full and Mapless installations.

- Backport the maintained libxml2 entity-parsing security fix in the database
  image and retain its exact source and build recipe alongside package notices.

- Retain rebuilt proxy/database Go dependency legal texts and the Go license
  alongside their existing runtime notices, and select Runner’s upstream
  license-corrected LDAP source dependency.

- Align Full and Mapless source pins with merged source-access links, license
  notice delivery and the public-documentation cleanup.

- Align installation platform guidance, managed-worker availability and historical
  notice-delivery descriptions with the current operator guides.

- Attribute the Full web source link to its pinned revision only when the actual
  build context is the clean managed Map checkout; custom builds keep a
  repository link without claiming an exact revision.

- Retain the rebuilt Caddy and gosu licenses and available upstream notices in
  their runtime images, alongside the unchanged binaries.

- Remove unused GnuPG package-acquisition tools from the database runtime image,
  preserving PostgreSQL, apt signature verification and existing privileges.

- Verify optional component source archives against every tracked Git blob;
  refuse omitted/altered files and unsupported LFS/submodule payloads before
  recording a completed delivery manifest.

- Provide separate source-built Full and Mapless installations on Windows 11
  Docker Desktop and Ubuntu 24.04/amd64, with explicit mode selection.
- Connect reviewed Gate jobs to separately enabled managed workers. Normal
  startup remains inert; each job requires its own finite authorization.
- Keep signing custody separate from execution, with credential grants,
  target/duration limits, cancellation and held-state recovery.
- Export original-run evidence and audit manifests, and reconcile stopped workers
  without replaying jobs or restoring spent permission.
- Preserve data through controlled updates, encrypted backup/restore and
  state-preserving Mapless recovery.
- Provide trusted local HTTPS, readiness diagnostics and operator instructions.
- Collect exact-pin component notices and optional source archives with explicit
  licensing and completeness limits.
- Protect agent-local credentials and retain secret scanning.
- Separate public user documentation from private planning and validation notes.

This is source-built software, not a published Community release.
See [support and safety limits](docs/limitations.md) for unresolved boundaries.
