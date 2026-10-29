# Alpha review checkpoint — 2026-10-28

> **Later manual review:** [Caddy v3 JWK exposure](caddy-v3-jwk-exposure.md)
> now traces the affected code and tests the shipped configuration against an ACME
> positive control. Older "reachability unestablished" statements below describe
> the preceding checkpoint. The dependency remains affected and no risk is accepted.

This checkpoint supersedes current-state claims in the 2026-10-27 strategy and
handoff snapshots. It does not accept risks or approve publication.

## Verified baseline

- Main revisions: distribution `524585c`, Map `5cb3b59` (#126), Runner `954aa63`
  (#95), Gate `77e9b22` (#18). Main CI passed and no PR was open at the initial audit.
- Primary checkouts were clean and their trees matched main, with no stashes.
  Gau branch `0fdb1c2` is tree-identical to Runner #89's merge `4fae92f`; no Gau handoff
  remains unfinished. Native Gau exclusion is enforced by Runner #94.
- The old Gate source/test worktrees are preserved; local-only files must not be
  deleted or interpreted as an active implementation queue without inspection.
- The installed distribution pinned Map #119, so #120–#126's new coverage and
  boundary features were merged application work but were not in that installation.

## Security evidence

[Run 40622056177](https://github.com/VardrSec/VardrSec/actions/runs/40622056177)
records clean distribution `524585cac788d08c529df58b4dd82a20029e7c1b`, Map
`6ea3792614d471058818ab1f59fb3ebd1466274d`, Runner
`954aa63fbd1b8d18faecf1708c28883fed511055` and Gate
`af29a93140b54cf5b684a06f552a05cd92f6dee6`. The receipt's five input hashes
match their Git blobs; all ten report hashes match. Independently counting every
raw vulnerability occurrence gives:

| Image | Critical | High | Unknown | Critical/high occurrences with fixed version |
| --- | ---: | ---: | ---: | ---: |
| API | 0 | 44 | 1 | 0 |
| Database | 1 | 61 | 5 | 0 |
| Proxy | 0 | 2 | 1 | 1 |
| Runner | 0 | 47 | 7 | 1 |
| Web | 0 | 43 | 1 | 0 |
| **Total** | **1** | **197** | **15** | **2** |

The three additional high occurrences over the historical 194 are the same
advisory, [CVE-2026-116587 / GHSA-mgcc-cww5-fp2q](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q):
Caddy go-jose/v4 4.1.5, Caddy go-jose/v3 3.0.5, and Nuclei go-jose/v4 4.1.4.
Upstream fixes v4 in 4.1.6 and lists no fixed v3 release. Counts are package/path
occurrences, not unique exploit paths. The existing 194 Debian high occurrences
and critical PostgreSQL/libxml2 occurrence remain unaccepted. Raw reports are retained.

## Corrections and component merges

- [Map #127](https://github.com/VardrSec/VardrMap/pull/127): use the resource's
  tenant for tenant-boundary drafts, matching classification. Fall back to the
  owner only when no resource tenant is declared. Conflicting resource tenants
  require a human choice; no last-case-wins resolution. Drafts remain all-skip,
  unpersisted and unqueued. Local backend suite: 1209 passed, one skipped.
- [Runner #96](https://github.com/VardrSec/VardrRunner/pull/96): rebuild Nuclei
  with go-jose/v4 4.1.6 and enforce that patch in the source receipt. Three negative
  regressions reject missing or vulnerable module records before execution.
  Local full suite: 1658 passed, ten skipped, 96.48% coverage; lint/format/types pass.
- Distribution candidate pins those exact PR heads, incorporating Map #120–#126,
  and rebuilds Caddy with go-jose/v4 4.1.6. Installed acceptance checks coverage,
  evidence-backed candidates, boundary panels and all-skip draft generation without
  changing cases, jobs or target traffic. No migration is added by these changes.

Map #127 merged as `e29bb0bfa295883c6bb7af5e69eb8510b8b19c3d`; Runner #96
merged as `5ac08f8871064575a5529e68cf472b9c0ed24b9d`. Both exact component
pins, plus the unchanged Gate pin, were reverified as ancestors of their main branches.
Map and Runner PR checks passed in full, including PostgreSQL/browser integration,
the OS/Python matrix and the real toolkit build.

## Verified rebuilt-image evidence

[Run 40757052765](https://github.com/VardrSec/VardrSec/actions/runs/40757052765)
collected the patched images from GitHub's clean PR merge commit
`434947e08e705fe71148e53e79d77fb341fd8d8e`, whose full tree equals reviewed
head `53f889f63d70bd3ad45983f264b3619d55152dce`. Five input hashes and ten
report hashes were independently verified and all raw findings recounted:

| Image | Critical | High | Unknown | Critical/high occurrences with fixed version |
| --- | ---: | ---: | ---: | ---: |
| API | 0 | 44 | 1 | 0 |
| Database | 1 | 61 | 5 | 0 |
| Proxy | 0 | 1 | 1 | 0 |
| Runner | 0 | 46 | 7 | 0 |
| Web | 0 | 43 | 1 | 0 |
| **Total** | **1** | **195** | **15** | **0** |

Both proxy and Runner SBOMs contain go-jose/v4 **4.1.6**. The two fixable
occurrences are removed; the remaining high occurrences are the existing 194 Debian
package/path occurrences and Caddy's go-jose/v3 advisory. The strict check was
explicitly rerun and exits **1 (blocked)** for all five images, as required.

The same run retains the raw `proxy-go-reachability` artifact from `govulncheck`
1.9.0 on the actual rebuilt Caddy binary: **0 reachable vulnerabilities**, zero in
imported packages, and one in a required module whose vulnerable code is not called.
This result covers only advisories known to that database. It does not establish the
new v3 JWK advisory's reachability: the official Go module index lacks that advisory
at this checkpoint. The single module-level result must not be attributed to v3
without its advisory ID; verbose output is now retained for that purpose. The v3
Trivy/GitHub finding stays open and unaccepted.
Runner's [container run 40756125456](https://github.com/VardrSec/VardrRunner/actions/runs/40756125456)
reports the unchanged reachable Nuclei OpenPGP advisory GO-2026-5932 and no
reachable advisory in the other shipped Go binaries.

Installed workflow and recovery results for the final integration head are recorded
in [distribution #40 checks](https://github.com/VardrSec/VardrSec/pull/40/checks).
The first installation run passed all six real Gate assessments, then correctly
rejected a fixture write lacking CSRF. Commit `70bc2fd` supplies the session's
`csrfToken`; no application protection was weakened. An additional local adapter
test passed the new surface assertions against Map's disposable API fixtures.
Later fixture/documentation changes do not alter the five image inputs above.
Do not infer that the v3 advisory disappeared because v4 was patched. No vulnerability suppression,
risk acceptance, release, image publication or deployment is authorized here.
The unfamiliar-user exercise, actual VPN validation, licensing review and remaining
release decisions retain their existing status in the [release checklist](community-alpha-release.md).


## Build-download reliability follow-up

After multiple independent failures and a failed retry at both `proxy.golang.org`
and `sum.golang.org`, [Runner #97](https://github.com/VardrSec/VardrRunner/pull/97)
sets `GODEBUG=http2client=0` only in Go builders, including the separate Gate stage. The exact distribution
pin is `65186ddb6c26c9d895f146a74decc52e08d3913e`. Downloads still use verified HTTPS
and the public checksum database; source versions, patches and binary receipts are
unchanged. Runtime CI asserts that the final toolkit inherits no `GODEBUG` setting.

This advances the Runner source commit beyond the #96 image evidence above, so a
fresh collection and installed acceptance are required for the new manifest.
Their results and main ancestry verification are recorded in
[distribution #40 checks](https://github.com/VardrSec/VardrSec/pull/40/checks) and its
merge record. The dated #96 reports are retained as remediation evidence, not
misrepresented as reports of the #97 source pin.

The corrected installed run [40758980959](https://github.com/VardrSec/VardrSec/actions/runs/40758980959)
passed the real UI coverage and same-tenant drafting path and restart checks.
Its preserved receipt records all six Gate scenarios, `boundary_draft_rendered: true`,
and vulnerable/fixed/unavailable coverage states of violation_candidate/conclusive/
inconclusive. The complete tool/network matrix passed on Ubuntu 22.04 and 24.04
in [run 40758981266](https://github.com/VardrSec/VardrSec/actions/runs/40758981266).
These results precede the build-transport-only pin advance; the final head repeats
the full checks rather than assuming that a build change proves acceptance.


The same build-only transport is used by the distribution's Caddy/gosu builders
and host-side age/govulncheck installation steps. The image collection job checks
that proxy, database and Runner runtime images contain no `GODEBUG` override.
TLS verification, checksum authentication, source versions and tool behavior stay
unchanged. This completes the same workaround across the actual Go build stages;
the first follow-up had omitted Gate's separate builder and hit another stream reset.


## Final-pin validation and Go database coverage limit

All checks for reviewed head `1292ef79aa1660d2c3eaf6520aa5b05b5f4b09e3` passed:
[Compose/recovery/updates](https://github.com/VardrSec/VardrSec/actions/runs/40762760959),
[Ubuntu tool/network matrix](https://github.com/VardrSec/VardrSec/actions/runs/40762760608),
[native trust](https://github.com/VardrSec/VardrSec/actions/runs/40762760593),
foundation and [image collection](https://github.com/VardrSec/VardrSec/actions/runs/40762760658).
The final collection records clean CI merge `7739c441d51b1f505792cd4009556d71bf68c263`,
tree-identical to that head. All five input hashes, ten report hashes, final component
pins, raw counts and both go-jose/v4 4.1.6 inventories were independently verified.
Counts remain **1 critical / 195 high / 15 unknown**, no critical/high fixed version;
strict review still exits 1. Runtime-image checks confirm no builder `GODEBUG` leaks.

The [official Go module index](https://vuln.go.dev/index/modules.json) listed only
GO-2023-2334, GO-2024-2631, GO-2025-3485 and GO-2026-4945 for go-jose/v3 at the
2026-10-28 audit. Fetching each official ID record confirmed that none aliases
CVE-2026-116587 or GHSA-mgcc-cww5-fp2q. Therefore a zero-reachable govulncheck
result is **not an affected-status determination for this new advisory**. The earlier
module-only attribution was unsupported and is corrected above. Actual v3 function
reachability/input exposure requires separate analysis; no exception is proposed.

The final documentation/verbose-report correction does not change application code,
source pins or image recipes. The PR retains the fresh raw evidence and requires
its exact final-head checks before merge. Runner #97 merged as
`6fb8800c175026fdd033262df3eb2dea939e9f70`; its exact pin is on main and its
merged tree matches the tested head.
