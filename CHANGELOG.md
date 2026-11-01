# Changelog

## Unreleased

- Advance only the VardrMap development pin to `41d3ef6` (Map #143). Relative to the previous pin
  `428be22` it adds Map's test-only changes: the integration acceptance now runs against the
  Runner and Gate commits this distribution pins (#142, fixing #140) and verifies Naabu results end
  to end into Map (#143). No application, API, migration or behavior change. Runner (`668dc56`) and
  Gate (`7f82e49`) are unchanged; release status and gates are unchanged.

- Add `docs/candidate-freeze.md`: the owner decisions that gate a candidate freeze, the human
  acceptance automation cannot provide, the exact verification run on the frozen commit (pins,
  workflows, component CI, image evidence against the register, the conditions behind each
  register decision, licensing refresh, reproducibility, documents), the freeze procedure and an
  unfilled evidence record. A freeze neither tags nor publishes. Documentation only; no gate or
  release status changes.

- Prepare the residual-risk register for the owner's approval: a nine-decision sheet (R1-R9) with each
  proposed conditional disposition, the exact conditions it depends on, the automatic safeguards that
  exist today (and the places where none does) and the re-verification required at the candidate
  freeze, an unfilled approval record, and a single recount history. The critical libxml2 finding is
  separately gated on a source search and a fix check at the freeze; Caddy, Nuclei and glibc stay
  explicit conditional limitations. The plan and checklist now state the current recount
  (1 critical / 195 high / 15 unknown, run 41252576786) instead of the superseded 25-unknown figure.
  Documentation only; nothing is accepted and no gate changes.

- Record the Nmap-free Community Alpha in the license inventory, release checklist, risk register
  and installation guide: Nmap is excluded from packaging and every image (enforced by Runner's
  container workflow, the tool/network fixture and image evidence), Naabu is the port-discovery
  tool, Map no longer offers Nmap, and Runner's retained opt-in integration code remains an open
  licensing question. Removing Nmap does not resolve other third-party obligations.
  Documentation only; no gate, license or support claim changes.

- Advance the development pins for the Nmap-free Community Alpha: Map to #141 (the Jobs Composer
  no longer offers Nmap and Host Enumeration is `naabu -> httpx`) and Runner to #103 (the
  `toolkit` image no longer installs Nmap; the Nmap integration is off unless an operator opts
  in with `VARDRRUNNER_ENABLE_NMAP=1` and their own installation). Gate is unchanged. Naabu is the
  supported port-discovery tool. Image evidence now rejects any image whose SBOM or package
  inventory contains `nmap` or `nmap-common`, and the tool/network fixture drops its Nmap checks,
  asserts that Nmap is absent from the Runner image and checks that raw sockets stay denied. The
  Map pin also brings Map's dependency updates (#137, #138) and test-only migration guard (#139);
  installed acceptance, recovery, update and role drills run against these pins. **Deploy order:**
  none beyond the usual rebuild; an installation that used `nmap` jobs must opt in and supply its
  own Nmap. Documentation of the licensing position follows in a separate change.

- Adopt the Apache License 2.0 for the distribution's original files: add the official
  unmodified `LICENSE` and a `NOTICE` naming Jorge Aquino as copyright holder (the only author
  of this repository, matching the owner's other repositories), and a README license section
  stating that it neither relicenses nor overrides VardrMap (AGPL-3.0), VardrRunner (MIT),
  VardrGate (Apache-2.0) or any third-party license. The license inventory and release
  checklist record the layered structure and mark the distribution-license decision
  complete; Nmap, transitive notices and any prebuilt-image redistribution remain open.
  No code, component license, release gate or support claim changes.

- Add `docs/platforms.md` and align platform wording: the packaged Docker Compose
  distribution is officially supported on Ubuntu 24.04, Docker's Linux-container requirement
  is separated from application requirements, native Map/Runner/Gate execution on Windows
  and Linux is recorded with its 2026-10-31 evidence and CI coverage, and future
  cross-platform milestones are listed as planning direction. Replaces "Linux-only alpha"
  wording. Documentation only; no support claim, gate or behavior changes.

- Note in the register and plan that the scanner database later rated glibc CVE-2026-84243 MEDIUM
  (recount 1 critical / 195 high / 15 unknown); it remains affected and unfixed. Documentation
  only; nothing is accepted and no gate changes.

- Record the remediation of the superuser API database role in the CVE-2026-84243 exposure
  review, register and release checklist. Documentation only; nothing is accepted and no
  gate changes.

- Run the API as a least-privilege PostgreSQL role (issue #52, Phase 1). New
  `python3 vardrsec.py database-role` creates `vardrmap_app` (no SUPERUSER, CREATEDB,
  CREATEROLE, REPLICATION or BYPASSRLS), hands it ownership of the application schema and
  verifies it over the network; `vardrmap` remains the administrator, used only inside the
  database container and by backup/restore, and its password never reaches the API.
  `install` runs the step before `start`, `configure` generates `POSTGRES_APP_PASSWORD`,
  and restore re-applies it after `pg_restore`. The Alembic startup migrations, Map code,
  database image and component pins are unchanged. **Deploy order for existing
  installations:** back up with the current version, update the checkout, run
  `python3 vardrsec.py database-role --backup DIR`, then `start`; Compose refuses to start
  until `POSTGRES_APP_PASSWORD` exists. See `docs/database-roles.md` and ADR 0003.
  Installed acceptance verifies the role flags, denied privileged operations, a fresh
  install, an existing-volume upgrade (refusals, rollback of a failed change, repeat,
  pre-change backup restore) and the existing recovery and update drills on the new role.
  A separate migration account (Phase 2) is not part of this change.

- Add a read-only runtime probe to the installed Ubuntu 24.04 acceptance job for the glibc
  gettext `LANGUAGE` review (CVE-2026-84243): installed locales, locale variables in the
  API, web, Runner and database containers (only those names are read), a harmless
  two-string gettext catalog tested under `C.UTF-8` and `en_US.utf8`, and the API
  database role's privilege flags. It starts no scan or job and changes no image,
  Compose setting, pin or release status; no risk is accepted.

- Add the glibc gettext `LANGUAGE` exposure review for CVE-2026-84243 and update the
  residual-risk register, release checklist and plan. No untrusted path to the vulnerable
  condition was identified in the sources of the shipped configuration; a conditional
  exception is proposed only, with the non-root impact limit stated. The runtime probe
  (see below) later confirmed the locale and environment conditions. Documentation only; no code, pin, Compose or release-status change, and no risk
  accepted.

- Refresh the Community Alpha release checklist, plan and residual-risk register to the
  current development pins (Map #134, Runner v0.54.0, Gate v0.2.0; #46/#47) and the
  2026-10-31 image recount from the raw reports: 1 critical / 195 high / 25 unknown.
  The critical and high occurrences are unchanged; ten additional unknown occurrences
  are glibc CVE-2026-84243, added to the register as unreviewed with no proposed
  disposition. Documentation only; no pin, Compose or release-status change, and no
  risk accepted.

- Consolidate agent instructions: `AGENTS.md` is the single source for Claude Code
  and Codex, now including the platform context, division of labour and verification
  notes that only `CLAUDE.md` carried; `CLAUDE.md` imports it. Documentation only;
  no pin, Compose or release-status change.

- Advance only the VardrMap development source pin to #134, including the
  read-only running-job hint (#133) and nonce-based **report-only** script CSP
  (#134). Runner v0.54.0 and Gate v0.2.0 remain unchanged. Re-run installed
  workflow, recovery, networking, and image checks before merging; do not
  enable CSP enforcement or change Community Alpha release status. The
  HSTS named-host browser verification remains separately tracked (Map #135).

- Advance the development distribution pins together to Map #132, Runner v0.54.0
  and Gate v0.2.0; keep source installation, image gates and Community Alpha
  publication status unchanged. Installed Gate acceptance now explicitly approves
  the three disposable fixture credential references before any job is claimed, so
  the new Runner credential boundary is exercised end to end. Fresh integration and
  image evidence must pass before merging; historical license inventories remain
  pinned to their recorded source snapshot and need regeneration for any release.

- Add `python3 vardrsec.py runner [--env NAME]... -- <command>`, which runs one Runner
  command in the installed image set (including `.active-images.json` after a
  controlled update or restore) and passes named variables from the caller's shell
  without putting values on a command line. The installation walkthrough uses it in
  place of plain `docker compose run`, which selects the development-tagged image.
  Correct the walkthrough's credential reference example to `value_env`.

- Replace the README's completed implementation queue with merged development
  capabilities and links to the actual remaining Community alpha release gates.
  Preserve source pins, acceptance limitations and unpublished status.

- Record the verified pinned-source license inventory and managed-tool notices,
  including the missing distribution license, exact Nmap metadata/source mismatch
  and transitive/artifact delivery gaps. Correct the source-build licensing assumption
  and reconcile alpha status with merged #40/#41 evidence. Documentation only; no
  license, packaging, risk acceptance or publication decision is made.

- Add the source-level Caddy v3 JWK exposure review and a bounded, TLS-verified
  loopback regression guard against the actual proxy binary. Shipped routes forward
  the test bytes; enabling ACME changes the parsing boundary. CI rejects unreviewed
  handler/admin/issuer/upstream/trust changes and retains hash-bound receipts.
  The v3 module remains affected, raw gates remain blocked and no risk is accepted.

- Advance Runner to #97 for verified HTTPS/HTTP/1.1 module downloads in builder stages
  after repeated upstream HTTP/2 stream resets. Apply the same setting to the Caddy/gosu
  builders and host build tools. CI verifies it is absent from all three runtime images.
  Runtime transport settings, source versions and integrity checks are unchanged; the new
  pin receives fresh installed/image checks.

- Integrate Map #127 (coverage, evidence-backed candidates, boundary hypotheses and
  corrected tenant-boundary drafts through #120–#127) with Runner #96's Nuclei go-jose
  fix. Rebuild Caddy 2.11.7 with go-jose 4.1.6 for CVE-2026-116587. Installed acceptance
  now verifies coverage and boundary drafting through the real browser without saving
  cases, queueing jobs or contacting a target. Both component PRs are merged and their exact
  pins are on main; final distribution validation is tracked in #40. Rebuilt image evidence
  verifies both fixed modules and 1 critical / 195 high / 15 unknown remaining; no risk accepted.

- Pin merged Runner #94/#95 (`954aa63`): the vulnerable native Gau archive is excluded
  from install and execution, and container CI now reports `govulncheck` reachability for every
  shipped Go binary, including Naabu (clean; Nuclei retains only the unfixable openpgp advisory).

- Add `python3 vardrsec.py install`: one command for a new checkout that runs the existing
  configure, sources, build, start and export-ca steps in order and prints the remaining manual
  trust and bootstrap steps. It is resumable after an interruption (an existing `.env` is kept, never
  regenerated) and refuses once the database volume exists; it changes no architecture and enrolls
  no trust. The controlled-updates CI job now uses it on a clean Ubuntu runner.

- Reconcile the plan, Gau review and security assessment with the final state: Gau remediated
  for the container and excluded natively, status set to release candidate preparation, and
  superseded rows marked. Documentation only.

- Record the owner decision to exclude the native Gau archive, enforced in Runner #94, and mark
  the Gau checklist item done. Documentation only.

- Add the Community Alpha residual-risk register: each unresolved finding with component,
  exposure assumptions, evidence and a proposed disposition for explicit owner decision.
  Nothing in it is accepted. Documentation only.

- Update the release checklist with current evidence and add the owner-decision section
  (native Gau, nmap redistribution, residual-risk acceptance) with recommendations.
  Documentation only.

- Pin merged Runner #93 (`5803bb9`): source-built tools use x/net 0.62.0 and goldmark 1.7.17 for
  reachable advisories newer than the frozen scan database. Nuclei keeps the unfixable
  unmaintained-openpgp advisory.

- Raise the proxy's x/net to 0.62.0 (GO-2026-6860 and GO-2026-6866, both reported reachable
  in the built Caddy by `govulncheck`) and the PostgreSQL image's gosu `moby/sys/user` to
  0.4.1 (GO-2026-6686, reachable). `govulncheck` reports nothing for either rebuilt binary.
  These advisories postdate the frozen image-scan database.

- Record the recounted image baseline after the Runner #91/#92 pin: 1 critical / 194 high,
  none with a published fixed version; all strict gates remain blocked and nothing is
  accepted as risk.

- Add a first-assessment walkthrough to the installation guide (engagement, client and
  authorization in the UI, review-only drafts, explicit Runner execution, evidence
  review) and record the UI-only researcher workflow verification in the plan.
  Documentation only.

- Pin merged Runner #91 and #92 (`bbe2850`): container httpx 1.12.0, Subfinder 2.17.0, FFUF 2.3.0
  and Nuclei 3.11.1 are rebuilt from recorded source with Go 1.27.3 and patched dependencies, extending the
  Katana/DNSx/Naabu/Gau contract. Native archives and runtime hash checks are unchanged.
  Image security gates remain blocked pending review of this pin's scan.

- Installed workflow acceptance no longer seeds client, testing window, scope or
  written authorization through the API: the real browser journey records them
  through the Map interface (merged Map #119, `6ea3792`) and the test then
  verifies what the backend holds.

- Record the exposure review of the remaining libxml2 and ncurses findings: no
  reachable path demonstrated in the packaged configuration, none accepted as risk,
  gates unchanged. Documentation only.

- Add networking and VPN guidance: when to use the native Runner, what is verified,
  and what remains unverified (genuine VPN routing, split tunnelling, kill switch).
  Documentation only; no host network, firewall or VPN behavior changes.

- Rebuild the gosu helper in the pinned PostgreSQL image from its v1.19.0 module with the
  distribution's patched Go 1.27.3 toolchain (`db/Dockerfile`). The reviewed PostgreSQL
  base digest and gosu release are unchanged; only the Go standard library bundled in
  that helper is replaced. Image evidence now builds the database image instead of
  pulling it. Remaining Debian-package findings in the base image are unchanged and
  unresolved.

- Pin merged Runner #89 (`4fae92f`, squash of reviewed head `0fdb1c2`): container Gau is rebuilt from
  checksum-verified upstream source with four hash-pinned substitutions that enable
  provider TLS verification and make provider failures fatal. Runner CI exercised
  untrusted, wrong-host, trusted, valid-empty, malformed and initialization cases
  through the producing handler. Native Gau archives do not gain the fix, no alpha
  tool-scope decision is made, and image security gates remain blocked pending the
  rescan of this pin.

- Pin merged Runner #88: build existing Naabu 2.6.1 with patched Go dependencies,
  recorded source provenance and unchanged runtime libpcap/privileges. Record
  audited DNSx integration evidence and the separately confirmed Gau provider TLS
  verification blocker; no dependency-only Gau rebuild is promoted.

- Pin merged Runner #87: extend recorded container source builds to existing
  DNSx 1.3.1, verify a real isolated DNS lookup and preserve native archives.
  Record independently audited Katana integration evidence; residual image
  findings and release gates remain blocked.

- Pin merged Runner #86: build existing Katana 1.8.0 with patched dependencies
  and explicit source provenance while retaining all nine tools, native archive
  installation and runtime integrity checks. Revalidate the combined development
  images; remaining security findings still block release.

- Align the existing age acceptance-tool builds with reviewed Go 1.27.3 and
  disable implicit compiler downloads. Keep age v1.3.2, backup format and
  application images unchanged; verify the existing encryption/recovery cases.

- Record partial Debian vulnerability exposure review with vendor conditions,
  split-package context and bounded local file probes. Retain all blocked image
  findings and the need for reviewed per-finding dispositions.

- Exercise first-run Runner key creation through the real Settings UI before
  authenticated CLI diagnostics and status reporting. Keep its one-time secret
  out of shared logs/screenshots and clarify the installation guide's key step.

- Rebuild the existing proxy with chi 5.4.0 to remove CVE-2026-114437 from
  the dependency inventory. Caddy version, standard modules and TLS configuration
  remain unchanged; other image-security findings remain under review.

- Record the verified clean Ubuntu first-run and residual security checkpoint;
  align current acceptance with the Linux-first alpha scope. Keep security,
  unfamiliar-user and experimental-platform limits explicit.

- Improve first-run prerequisite errors and safe retry of an interrupted initial
  source fetch; preserve existing configuration and changed checkouts. Expose the
  existing generated-password bootstrap mode and display the public CA fingerprint.
  Verify genuinely clean Ubuntu setup, explicit native CA enrollment/removal and
  CLI bootstrap in the installed acceptance job. No automatic trust or routing changes.

- Adopt the owner's Linux-first Community Alpha stabilization priorities and
  refresh proxy OS packages during the development image build. Remaining image
  vulnerability findings still require review; no release is published.

- Add explicit development image SBOM/vulnerability evidence collection and a
  separate strict review command. Blocking findings remain visible; no image
  publication or release readiness is implied by collection success.

- Record the agreed component responsibilities and the first readiness/diagnostics
  implementation reviews. Add a candidate source manifest and validation CI.
- Compose lifecycle, local authentication, component images and the Map status UI
  remain planned; no runnable distribution or release is published by this change.
