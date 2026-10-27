# VardrSec distribution — Claude instructions

@AGENTS.md

## Platform context (applies even when this repo is opened on its own)
VardrSec is a modular, local-first security research platform made of four independent repositories: this distribution (`VardrSec/VardrSec`), `VardrMap` (research interface, engagements, findings, evidence, reports), `VardrRunner` (explicit tool execution, credentials, diagnostics) and `VardrGate` (Go multi-identity API authorization assessment). This repository is the distribution layer, not a replacement for the others.

Immediate target: **Community Alpha v0.1.0 on Ubuntu 24.04/amd64**. The authoritative, version-controlled plan is `docs/community-alpha.md`; read `docs/acceptance.md` and `docs/alpha-security-assessment.md` for evidence. Dated status documents (`docs/alpha-checkpoint-*.md`, the owner's `VardrSec_CLAUDE_HANDOFF_PLAN.md`) are snapshots: current Git state, tests and verified acceptance results outrank them.

Cross-repository rules that hold here too: explicit operator-controlled execution; tenant/ownership isolation and human-reviewed scope; credentials and engagement data never in logs, commits or reports; compatibility check whenever a component interface changes; tests for behavior changes; security-sensitive changes get review before merge; no feature expansion during stabilization.

## Division of labour
- Map owns readiness reporting (`/ready`) and the UI; Runner owns `doctor --platform` and execution; Gate is invoked through Runner or standalone; the distribution wires, pins, backs up and recovers them.
- Fix a component defect in its own repository, then integrate the reviewed commit here in a separate focused PR.

## Git hygiene
- `git fetch` first; local `main` is routinely behind. Branch from `origin/main`. No force-push, reset, or deleting branches/worktrees without authorization.
- Never push, merge, tag, publish images or deploy unless explicitly told to.

## Verification
`python -m unittest discover -s tests -p 'test_*.py'` for unit tests (as in `.github/workflows/compose.yml`); installed workflow, recovery, trust and image-evidence checks run in CI (`.github/workflows`) and are described in `docs/acceptance.md`.
