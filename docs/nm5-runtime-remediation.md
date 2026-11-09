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
