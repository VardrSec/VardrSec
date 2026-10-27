# Alpha security assessment — in progress

Assessment checkpoint, 2026-10-27. This is not release approval. The strict image
vulnerability gate remains blocked, raw reports are retained, and no exception or
blanket suppression is introduced. Task 1 of the [alpha plan](community-alpha.md)
remains in progress pending residual affected-status/exposure review and fixes.

## Implemented remediation

- [Map #117](https://github.com/VardrSec/VardrMap/pull/117) pins Python/Node Debian
  Trixie bases and removes the unused global npm/npx dependency tree from the web
  runtime. npm remains in the build stage; native development is unchanged.
- [Runner #85](https://github.com/VardrSec/VardrRunner/pull/85) pins its Python/Trixie
  base and patched Go 1.27.3 Gate builder, and verifies the five official Subfinder
  2.17.0 archives before updating that existing tool pin.
- The proxy retains Caddy 2.11.7, rebuilt with pinned Go 1.27.3 and x/net 0.60.0;
  its Alpine packages are refreshed. The small standard-module entry point keeps
  Caddy version metadata available. TLS configuration, installed CA storage and
  the existing file-capability boundary are preserved. This follows Caddy's
  [documented source-build approach](https://caddyserver.com/docs/build).

Local checkpoints reduced critical scanner occurrences from 13 to 7, and high
occurrences from 518 to 460 after the Map/Runner/OS refresh. The subsequent proxy
rebuild review scan reports zero critical/high occurrences, removing five more
high occurrences. These are package/path occurrences, not unique advisories or
confirmed exploit paths. Source-pinned CI receipts are the candidate evidence;
the local checkpoints do not establish release readiness.

Runtime probes verified API SQLite 3.46.1, non-root Map users and absence of runtime
npm. Frontend lint/typecheck, 212 tests and production build passed; Runner's full
suite/static checks and the real bounded tool/network fixture passed. Proxy leaf
renewal/restart retained CA hashes and key permissions. Installed/recovery/update
CI must verify the combined image set before this distribution change merges.

## Residual critical findings

| Finding / location | Current assessment and required action |
| --- | --- |
| CVE-2025-68121 in dnsx, gau and Naabu Go runtimes | The released binaries remain old; these tools are already on their latest upstream releases. The [Go advisory](https://pkg.go.dev/vuln/GO-2026-4337) concerns TLS session resumption after CA configuration mutation. Review binary symbols and actual client configuration, then use verified patched artifacts/rebuilds where exposed. Version presence alone does not establish exploitability or clearance. |
| CVE-2025-68121 in PostgreSQL's gosu helper | A privilege-switch helper is not a TLS service. Binary-symbol evidence is needed before a scoped affected-status disposition; do not change PostgreSQL base variant, data ownership or collation merely to change a scanner count. Raw reporting remains intact. |
| CVE-2026-33815 / CVE-2026-33816 in Katana's pgx dependency | The [Go report](https://pkg.go.dev/vuln/GO-2026-4772) identifies server-protocol decoding symbols and a fixed dependency version. Determine whether those symbols occur in the actual crawler binary and review [upstream context](https://github.com/jackc/pgx/issues/2530). No finding is accepted or hidden by this checkpoint. |
| CVE-2026-6653 in PostgreSQL libxml2 | [Debian](https://security-tracker.debian.org/tracker/CVE-2026-6653) retains affected stable packages with vendor priority notes. Review PostgreSQL XML-feature/input exposure and available vendor updates; do not mix packages from another Debian release. This remains unresolved. |

## Remaining high findings and review boundaries

The refreshed API/web high findings have no fixed-version entries in the current
scanner database. Preserve vendor package status and investigate plausible input
paths; lack of a packaged fix is not a disposition. Runner retains numerous
findings in bundled Go runtimes/dependencies, many with published fixed versions.
Prioritize verified upstream patches and symbol/exposure assessment. Full SBOMs,
package paths, installed/fixed versions, source URLs and counts remain available
in the unfiltered [image evidence](image-evidence.md) artifacts.

The former bookworm zlib MiniZip critical finding illustrates why affected-status
matters: [Debian documents](https://security-tracker.debian.org/tracker/CVE-2023-45853)
that the vulnerable contrib code is not built into those binary packages. The
Trixie refresh removes that old package baseline; no global ignore rule was added.
Binary analysis can narrow symbol presence but cannot prove all runtime paths or
eliminate reflection/unsafe-analysis limitations. Preserve that uncertainty.

## Failures and complexity observed

A retained Windows development checkout had an unreadable `.pytest_cache`, which
prevented Docker context transfer even with an ignore entry. A clean tracked-source
snapshot built successfully; the cache was left untouched and no ineffective
ignore change was retained. This is not evidence of a clean-Ubuntu installation
failure. The new clean-install exercise must use a fresh checkout and record its
own failures.

Existing diagnostics, backup/update implementations and workflow fixtures remain
the implementation path. Further installer layers, general exception frameworks
or broad application refactors are unnecessary for this checkpoint. The next
work is residual security review followed by the phase-1 clean Ubuntu/setup
tasks; release publication remains a separate reviewed action.
