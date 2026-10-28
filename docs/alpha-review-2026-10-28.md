# Alpha review checkpoint — 2026-10-28

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

## Candidate corrections

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

Candidate validation and refreshed image counts are pending CI. Do not infer that
the v3 advisory disappeared because v4 was patched. No vulnerability suppression,
risk acceptance, release, image publication or deployment is authorized here.
The unfamiliar-user exercise, actual VPN validation, licensing review and remaining
release decisions retain their existing status in the [release checklist](community-alpha-release.md).
