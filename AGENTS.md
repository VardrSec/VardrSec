# VardrSec distribution — agent instructions

Shared rules for every coding agent (Claude Code imports this file from `CLAUDE.md`;
Codex reads it directly). They must hold even when this repository is cloned on its own.

VardrSec is a modular, local-first security research platform made of four
independent repositories: this distribution, VardrMap (research interface,
engagements, findings, evidence, reports, `/ready`), VardrRunner (explicit tool
execution, credentials, `doctor --platform`) and VardrGate (Go multi-identity API
authorization assessment, invoked through Runner or standalone). This repository
wires, pins, backs up and recovers them; it does not replace them.

Current target: **Community Alpha v0.1.0 on Ubuntu 24.04/amd64.** The authoritative
plan is [`docs/community-alpha.md`](docs/community-alpha.md); evidence is in
[`docs/acceptance.md`](docs/acceptance.md) and
[`docs/alpha-security-assessment.md`](docs/alpha-security-assessment.md). Dated
status documents (`docs/alpha-checkpoint-*.md`, local handoff notes) are snapshots:
current Git state, tests and verified acceptance results outrank them. Do not copy the
roadmap into instruction files.

## Safety floor
- Starting the platform must not start scans or a background Runner. No tool
  execution without explicit authorization.
- Never commit credentials, local environment files, private engagement data, tool
  output or machine-specific paths.
- No force-push, history rewrite, release, tag, image publication, licensing change or
  deployment without explicit authorization.
- `git fetch && git status -sb` and `gh run list --limit 1` before starting; branch
  from `origin/main`.
- No AI attribution: no `Co-Authored-By` trailers or "Generated with" lines.

## Ownership
- This repository owns Docker Compose installation, startup, stopping, controlled
  updates, compatible component pins, HTTPS/trust, backup and recovery documentation.
- Preserve the separate Map, Runner and Gate repositories. Do not copy an engine or
  application here, or introduce another diagnostics implementation: Map reports
  readiness, Runner diagnoses and executes only when invoked, Gate assesses.
- Fix a component defect in its own repository, then integrate the reviewed commit
  here in a separate focused PR.

## Pins and releases
- Components are consumed through exact commit pins in `versions.json`. Never advance
  a pin silently or without rerunning the installed acceptance workflow. A pin change
  is its own verified PR. `versions.json` is a development compatibility record, not a
  release.
- Never present missing images, scripts or Compose services as runnable; source pins
  alone do not establish a deployable release.
- Do not choose native/container packaging or authentication by implication; record
  those decisions separately.
- Add no scanning engines, tools, frameworks or Enterprise features during alpha
  stabilization.

## Operations safeguards
- Stopping the platform preserves volumes. Updates account for migrations, verified
  backups and recovery, not merely image versions. Preserve the backup, encrypted
  restore and failed-update recovery safeguards.
- Keep HTTPS/trust and certificate-renewal behavior as documented and accepted.
- Do not mount the Docker socket into Runner to perform diagnostics.
- Keep raw vulnerability reports. Never add blanket suppression or convert an
  unresolved finding into an accepted risk without explicit owner authorization.

## Working rules
- Read the README and architecture decisions before implementation. Distinguish agreed
  intent, code in review, released artifacts and verified deployments.
- Use small reviewed changes; update `CHANGELOG.md`.
- Unit tests: `python -m unittest discover -s tests -p 'test_*.py'` (as in
  `.github/workflows/compose.yml`). Installed workflow, recovery, trust and
  image-evidence checks run in CI and are described in `docs/acceptance.md`.
- Docs-only changes need a diff, link check and `git diff --check`, not application suites.
- `artifacts/` and `.sources/` are untracked local evidence and source snapshots:
  never delete or edit them.
