# NM-5 targeted runtime remediation

Status: implementation under review, not rebuilt-image or release acceptance.

The existing [image-evidence run 42543020270](https://github.com/VardrSec/VardrSec/actions/runs/42543020270)
collected the current Map `c983a60`, Runner `dec2ac6` and Gate `57cfedf` cohort.
Its receipt records PR merge checkout `4c252745`, incorporating reviewed head
`3215da3`. Collection succeeded; every image vulnerability gate remains blocked.

The retained reports recount 1 critical, 223 high and 8 unknown occurrences:

| Image | Critical | High | Unknown |
|---|---:|---:|---:|
| API | 0 | 51 | 0 |
| Database | 1 | 68 | 1 |
| Proxy | 0 | 1 | 1 |
| Runner | 0 | 53 | 6 |
| Web | 0 | 50 | 0 |

These replace neither the historical raw reports nor owner risk decisions.
The older register's 1/195/15 recount and claim of no fixable high findings are
historical observations, not the current image state.

Sixteen high occurrences now list fixed versions across the API, database,
Runner and web images: apt/libapt-pkg7.0 and zlib1g. The targeted implementation
keeps base digests and Debian suites unchanged, upgrades only those installed
packages and checks minimum fixed versions. Debian records
[apt 3.0.4 for trixie security](https://security-tracker.debian.org/tracker/CVE-2026-109518);
the zlib minimum is `1:1.3.dfsg+really1.3.1-1+deb13u1` for CVE-2026-76844 and
CVE-2026-85091. An unavailable fixed version must fail the build.

The existing proxy symbol-level report additionally identifies GO-2026-6865
in klauspost/compress 1.20.1. Its build recipe raises only that dependency to
[1.20.2](https://github.com/klauspost/compress/releases/tag/v1.20.2), retaining
the Caddy release, toolchain, base digest and runtime privileges.

Rebuild and reuse the existing image-evidence and installed compatibility jobs
before claiming remediation. No new scanner or test framework is required.
Component recipe changes belong in their own repositories; integrating their
pins remains a separate installed-acceptance PR. No current pin is advanced here.
The remaining libxml2 critical and other unresolved findings are not waived.

## Verified distribution recipe result

The [PR77 rebuilt reports](https://github.com/VardrSec/VardrSec/actions/runs/42545355995)
verify database apt/libapt `3.0.4` and the stated zlib minimum. Compared with the
baseline, four high and one medium database occurrences are removed. The proxy
binary contains compress `1.20.2`; its symbol report records no reachable or
imported-package vulnerabilities and no GO-2026-6865. Module-only findings remain.
The cohort still used the older component pins, so API, Runner and web counts
were unchanged: total 1 critical / 219 high / 8 unknown. Every vulnerability gate
remained blocked. All required installed/recovery/update checks passed before
PR77 merged as `72f1497`.

The next separate compatibility candidate pins Map `55458b7` (PR154) and Runner
`519c047` (PR120), retaining Gate `57cfedf`. These add the same targeted package
remediation to API, web and Runner runtime stages. Its matched installed and
rebuilt-image results remain pending; no final aggregate reduction is claimed.

## Additional register coverage required

The current reports include three SQLite IDs absent from the historical register,
each in API, database, Runner and web: 12 high occurrences in total. Debian's
tracker lists Trixie `3.46.1-7+deb13u2` as vulnerable without a fixed Trixie
package; upstream fixes exist. The recorded triggers are:

- [CVE-2026-119373](https://security-tracker.debian.org/tracker/CVE-2026-119373):
  FTS5 negative rowids with prefix queries.
- [CVE-2026-119374](https://security-tracker.debian.org/tracker/CVE-2026-119374):
  deleting a corrupted FTS5 index with secure-delete enabled.
- [CVE-2026-119379](https://security-tracker.debian.org/tracker/CVE-2026-119379):
  crafted session changesets supplied to `sqlite3changeset_apply()`.

Debian's `no-dsa`/minor classification is distinct from the retained scanner's
high severity. Neither establishes application exposure, changes the raw reports
or accepts this distribution's risk. No switch to an unstable suite or broad
SQLite replacement is proposed. Current exposure review and owner disposition
remain required before release; the old decision sheet does not cover these IDs.

Bounded source review found Compose API configured for PostgreSQL (`compose.yaml`),
while native/custom Map URLs can select SQLite (`backend/db.py`). Runner uses
SQLite for its production journal (`vardrrunner/journal.py`), including Full and
Mapless operation; it must not be classified as unused. Searches of the tracked
Map and Runner production sources found no direct FTS5, virtual-table, changeset
or extension-loading entrypoint. This narrows the identified trigger paths but
does not establish an unaffected status: crafted/restored local databases and
dependency behavior remain uncertainties. Debian package findings do not
automatically establish native Windows Python exposure or its library version.
