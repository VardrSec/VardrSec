# Changelog

## Unreleased

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
