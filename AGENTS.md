# VardrSec distribution instructions

Shared rules for every coding agent (Claude and Codex). `CLAUDE.md` imports this file.

## Ownership
- This repository owns Docker Compose installation, startup, stopping, controlled
  updates, compatible component pins, HTTPS/trust, backup and recovery documentation.
- Preserve the separate Map, Runner and Gate source repositories. Do not copy an
  engine or application here, or introduce another diagnostics implementation.
- Runner diagnoses and executes only when explicitly invoked. Map exposes its
  readiness and displays reported status. Gate performs authorization assessment.
- Components are consumed through exact commit pins in `versions.json`. Never
  advance one pin silently or without rerunning the installed acceptance workflow.
  `versions.json` is a development compatibility record, not a release.
- Starting the platform must not start scans or a background Runner.

## Working rules
- Read the README and architecture decisions before implementation. Distinguish
  agreed intent, code in review, released artifacts and verified deployments.
- Current scope and priorities live in `docs/community-alpha.md`; do not copy the
  roadmap into instruction files. Add no scanning engines, tools, frameworks or
  Enterprise features during alpha stabilization.
- Use small reviewed changes. Never present missing images, scripts or Compose
  services as runnable; source pins alone do not establish a deployable release.
- Stopping the platform preserves volumes. Updates must account for migrations,
  verified backups and recovery, not merely switching image versions. Preserve the
  backup, encrypted restore and failed-update recovery safeguards.
- Keep raw vulnerability reports. Never add blanket suppression or convert an
  unresolved finding into an accepted risk without explicit owner authorization.
- Do not commit credentials, local environment files, private engagement data,
  tool output or machine-specific paths. Do not mount the Docker socket into
  Runner to perform diagnostics.
- Image publication, licensing changes, releases and deployment require explicit
  authorization. Do not choose native/container packaging or authentication by
  implication; record those decisions separately.
- Docs-only changes need a diff, link check and `git diff --check`, not application suites.
