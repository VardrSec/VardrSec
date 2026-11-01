# Community Alpha v0.1.0 candidate-freeze checklist

Status: **checklist only. Nothing is frozen, tagged, published or approved.** A freeze is a
commit on the distribution's `main` whose pins, documents and evidence are final for review.
It does not publish images, binaries, a tag or a release; those need the owner's explicit
authorization ([checklist item 10](community-alpha-release.md)). `versions.json` keeps
`status: development`, `distribution_release: null` and `runnable: false` until then.

## Decided scope (owner, 2026-10-31)

Source-built Ubuntu 24.04/amd64 distribution only; no published images or binaries; Naabu is the
default and supported port-discovery tool; Runner's disabled, operator-opt-in Nmap code is
preserved and Nmap is not bundled, installed or invoked; every repository license is unchanged
(distribution Apache-2.0, Map AGPL-3.0, Runner MIT, Gate Apache-2.0, Forge unlicensed).

## A. Owner decisions that gate the freeze

| # | Decision | Where | State |
| --- | --- | --- | --- |
| 1 | Approve, reject or modify R1-R9, with the libxml2 critical (R3) approved separately | [register decision sheet](residual-risk-register.md#owner-decision-sheet) | **Pending** |
| 2 | Choose the Map pin: keep `428be22`, or advance to include the test-only integration fixes (VardrMap #142, #143) after the checks below | [versions.json](../versions.json) | **Pending** (a separate verified PR if advanced) |
| 3 | Whether to keep Runner's disabled Nmap code or remove it (preserved for now; its licensing question stays open) | [inventory](release-license-inventory.md#nmap-excluded-from-packaging-retained-integration-code-is-a-separate-question) | Preserved; legal question open |
| 4 | Whether re-observation should keep earlier service name/product/version when a scan supplies none (today they are blanked) | VardrMap `services` upsert | **Pending**, not blocking |
| 5 | Authorize any tag, image publication or announcement | checklist item 10 | **Not requested** |

## B. Human acceptance that automation cannot provide

| Requirement | Why a person or environment is needed | Reference |
| --- | --- | --- |
| Unfamiliar-user installation and first assessment, timed, with friction recorded | Needs a real participant and a fresh Ubuntu 24.04 machine | [first-user-test.md](first-user-test.md); checklist item 4 |
| Map #135: HSTS upgrade in isolated named-host Chrome and Firefox profiles | Firefox is absent here and the local Caddy CA is untrusted; no trust-store changes were made | [VardrMap #135](https://github.com/VardrSec/VardrMap/issues/135) |
| AI suggest/triage with a real Anthropic key | Map now pins the anthropic 2.x SDK; only a mocked transport was exercised | Map `routers/findings.py`, `routers/scans.py` |
| Genuine VPN routing | Needs a VPN; otherwise ship it as the documented, unverified limitation with the native-Runner fallback | [networking.md](networking.md) |
| Upstream glibc advisory text and patch status | sourceware.org blocked automated retrieval | [glibc review](glibc-gettext-language-exposure.md) |
| Native Runner on a host: glibc and tool installs | Host-specific; the release notes must say the host's glibc is the operator's | [platforms.md](platforms.md) |

## C. Verification Claude runs at the freeze commit

All on the exact commit being frozen, from a clean checkout, recording the result and link in
section E. Any red result stops the freeze.

1. **Pins.** Each commit in `versions.json` is an ancestor of its repository's `main`
   (`git merge-base --is-ancestor <pin> origin/main`); the manifest job passes. Gate stays v0.2.0.
2. **Workflows on the frozen commit are green:** Distribution foundation; Compose acceptance
   (fresh install, installed Gate workflow, role drill, glibc probe, recovery drill, controlled
   updates); Tool and network acceptance on Ubuntu 22.04 and 24.04; Image evidence collection;
   Native certificate trust. Checklist items 3, 5, 6 and 7 are re-recorded from these runs.
3. **Component CI at the pins:** Runner CI (Windows, macOS, Ubuntu 3.10-3.14) and container job;
   Map CI including PostgreSQL migrations as the administrator and as a plain role, the
   integration acceptance on the pinned Runner and Gate, and the frontend; Gate CI.
4. **Image evidence versus the register.** `image_evidence.py check` still exits 1 by design. The
   recount equals the register's current figure or the difference is explained row by row; every
   critical, high and unknown ID appears in the register; no critical or high has a fixed version
   (a new one is a blocker); no SBOM contains `nmap` or `nmap-common`.
5. **Conditions behind the decision sheet** (what each approval depends on):
   - R1: `docker inspect` of each running container shows not privileged, no `CapAdd` beyond
     `NET_BIND_SERVICE` and no socket mount; effective capabilities read from `/proc/1/status`.
   - R3: search Map's backend, migrations and raw SQL at the pinned commit for `xmlparse`, `xpath`,
     `xmltable`, `xmlelement`, `xmlforest`, `xmlagg` and `::xml`; confirm libxml2 is still unfixed in
     the pinned Trixie suite and the PostgreSQL image digest is unchanged.
   - R4: the `glibc-locale-exposure` receipt from the frozen run.
   - R5: `proxy-jwk-boundary` and `proxy-go-reachability` from the frozen image-evidence run;
     Caddyfile and dependency recipe unchanged since the review.
   - R6: Runner's `govulncheck` report step green; no template bundle in any image.
   - R2, R7, R9: repeat the recorded source searches; Dalfox release check; Gau exclusion test.
6. **Licensing refresh.** `LICENSE` hash matches the official Apache-2.0 text; the Map, Runner and
   Gate licenses are unchanged; the inventory's SBOM license-metadata counts are regenerated from the
   frozen images; Nmap absence confirmed; transitive notices remain listed as open.
7. **Reproducibility (item 6).** Re-run the partial-reproducibility checks in the
   [checklist](community-alpha-release.md#reproducibility-evidence-2026-10-27): ancestry, base-image
   digests, package inventories from two builds, Gate and FFUF byte-identical builds.
8. **Documents.** Release notes and limitations are complete (below); relative links resolve;
   `git diff --check` is clean; the changelog states the deploy order.

Limitations the release notes must state: source-built only, no published images; Ubuntu 24.04
only, Windows/macOS Docker Desktop experimental, native components documented but no integrated
native install; genuine VPN unverified; native Gau excluded and Nmap unsupported (opt-in, own
installation); the existing-installation `database-role` upgrade; accepted conditional limitations
verbatim from the approved register rows; the API login can alter its own tables (Phase 2 deferred).

## D. Freeze procedure

1. Owner completes section A items 1 and 2; human items in B are scheduled or accepted as
   documented limitations.
2. If the pin changes, merge that pin PR alone after its own acceptance.
3. Claude runs section C on the candidate commit and fills section E.
4. Owner reviews section E and the approval record; only then is the commit called the candidate.
5. Tagging, publishing and announcing are separate authorizations and are not part of the freeze.

## E. Evidence record (filled at the freeze)

| Check | Evidence link | Result |
| --- | --- | --- |
| C1 Pins and ancestry | | Not run |
| C2 Distribution workflows | | Not run |
| C3 Component CI | | Not run |
| C4 Image evidence versus register | | Not run |
| C5 Decision-sheet conditions (R1-R9) | | Not run |
| C6 Licensing refresh | | Not run |
| C7 Reproducibility | | Not run |
| C8 Documents | | Not run |
| B Human acceptance items | | Not run |
