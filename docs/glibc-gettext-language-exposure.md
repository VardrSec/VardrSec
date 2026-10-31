# glibc gettext `LANGUAGE` exposure review — CVE-2026-84243, 2026-10-31

**Status: proposed conditional residual-risk exception. Not formally accepted.** The
owner approved documenting it as a proposal on 2026-10-31; no risk is accepted, no
release gate is cleared and release readiness is unchanged. The ten raw occurrences
remain and strict image checking still exits 1.

**Finding: the vulnerable glibc is present in four images, but no path was identified
by which an untrusted party can set the environment of a glibc-gettext program, and the
API, web and Runner images lack the second precondition (a non-`C` locale).** The
first statement is a source-review negative finding. The second was confirmed at
runtime on 2026-10-31 in the disposable Ubuntu 24.04 acceptance environment (see
[Verification status](#verification-status)). A related finding needs a separate
review: the API's database role is a PostgreSQL superuser. This is a
configuration-specific exposure assessment, not a claim that glibc is patched or a
scanner suppression.

## Vulnerability

glibc's gettext functions accept `LANGUAGE` entries containing `/` or equal to `..`
unless the program is setuid/setgid (`AT_SECURE`). A caller who controls `LANGUAGE`
can make a program load a `.mo` message catalog from an arbitrary path; a crafted
catalog can crash it or supply mismatched format directives, which may allow code
execution with the program's privileges. The CVE-2014-0475 fix did not cover
`LANGUAGE`.

| Fact | Source |
| --- | --- |
| CVSS 3.1 7.0 High, `AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`; CWE-22; finder Florian Weimer | [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-84243) (CNA: glibc) |
| CISA SSVC: exploitation none, automatable no, technical impact total | CVE record, CISA ADP |
| Needs another installed locale selected (`LANG`/`LC_ALL`); `LANGUAGE` is used only when `LC_MESSAGES` is not `C`, `C.<encoding>` or `POSIX` | CVE record; [Debian bug 1152640](https://bugs.debian.org/1152640) |
| Reporter's example: an SSH server forwarding `LANGUAGE`/`LANG` (`AcceptEnv`) to a forced-command account, plus a readable crafted file | Debian bug 1152640 |
| Trixie `2.41-12+deb13u4`, bookworm and sid/forky `2.43-7` all vulnerable; **no fixed version anywhere**; no `no-dsa` tag; no maintainer reply on the bug | [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-84243) |
| Upstream: [advisory GLIBC-SA-2026-0025](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0025), [bug 17142](https://sourceware.org/bugzilla/show_bug.cgi?id=17142), patch posted to [libc-alpha](https://inbox.sourceware.org/libc-alpha/20261012112453.47383-1-avinal.xlvii@gmail.com) | CVE record references |

Limit: sourceware.org blocked automated retrieval, so the upstream advisory text, bug
discussion and patch merge status were **not read**. The facts above come from the CVE
record and the Debian tracker and bug. Whether upstream has merged a fix is unknown.

## Affected images (source-verified: raw reports of run 41175264942)

All ten occurrences are `affected`, `Unknown` severity, no fixed version, glibc
`2.41-12+deb13u4`: API (`libc6`, `libc-bin`), web (same), Runner (same) and database
(`libc6`, `libc-bin`, `libc-l10n`, `locales`). The Caddy proxy image is Alpine/musl and
has no occurrence; musl was not otherwise assessed.

| Image | Runs as | Image `LANG` | Non-`C` locale package (SBOM) |
| --- | --- | --- | --- |
| API | 10001 | `C.UTF-8` | None (`locales`/`libc-l10n` absent) |
| Web | `node` | unset | None |
| Runner | 10001 | `C.UTF-8` | None |
| Database | `postgres` after `gosu` | `en_US.utf8` | `locales`, `libc-l10n` |

## Verification status

| Claim | Class | Basis |
| --- | --- | --- |
| Ten unfixed glibc occurrences in four images | **Source-verified** | Raw Trivy reports, CI run 41175264942 |
| Image `LANG`/user settings | **Source-verified** | Image configuration in the same receipts |
| No `LANGUAGE`, `LANG`, `LC_*`, `LOCPATH` in `compose.yaml` | **Source-verified** | `compose.yaml` at distribution `2149361` |
| No path from requests, jobs or targets to process environments | **Source-verified, negative** | Searches recorded below, at the pinned commits |
| API/web/Runner contain only `C`/`C.utf8`/`POSIX` locales | **Runtime-verified** | `locale -a` in each container, CI run 41221261206 |
| Database image contains `en_US.utf8` in addition | **Runtime-verified** | Same run |
| No `LANGUAGE`, `LC_*` or `LOCPATH` in any container; `LANG` is `C.UTF-8` (API, Runner), unset (web), `en_US.utf8` (database) | **Runtime-verified** | Locale variables read from `/proc/1/environ` (API, web, database) and `env` in a one-off container (Runner), same run |
| `LANGUAGE` (ordinary and `../` traversal) is ignored under `C.UTF-8` | **Runtime-verified, bounded** | Harmless catalog probe through bash `$"…"`, all four images, glibc 2.41; the plain-`C` default of the web image is short-circuited by bash, so only the `C.UTF-8` result there is glibc evidence |
| The probe and fixture are valid, and the traversal behavior exists in this glibc | **Runtime-verified (positive control)** | Database image under `en_US.utf8`: both the ordinary and the `../xx` catalog loaded |
| The API database role is a PostgreSQL superuser | **Runtime-verified: true** | `rolsuper`, `rolcreaterole`, `rolcreatedb` and `rolbypassrls` are all true for role `vardrmap`, same run. **Flagged for separate security review** |
| Behavior of Python, Node and PostgreSQL processes themselves | **Not tested** | Probe uses bash as the gettext caller; the logic is in libc, but no other program was run |
| Upstream fix status, advisory text | **Unknown** | sourceware.org was unreachable |

## No untrusted environment-control path identified (evidence record)

This is a negative finding: it is limited to the searches below and does not prove that
no path exists. Pins are those in `versions.json` at `2149361`: Map `696a8bf`, Runner
`854b973`, Gate `7f82e49`; searches ran with `git grep` at those commits.

- **Compose:** services set only the variables listed in `compose.yaml`; none is a
  locale or gettext variable. Operator-supplied values are the documented secrets and
  ports.
- **Map API (backend):** a search for `subprocess`, `os.system`, `Popen`,
  `os.environ[...]`, `putenv`, `os.exec*` and `create_subprocess*` finds uses only in
  test code. No `gettext`, `setlocale`, `LANGUAGE`, `LC_*` or `LOCPATH` in application
  code; Python's `gettext` module is pure Python and does not call libc.
- **Map web:** a search for `child_process`, `spawn`, `exec*` and `process.env` writes
  finds nothing in application code; Node does not use libc gettext.
- **Runner:** no assignment to `os.environ`, `putenv` or `environ.update`. Tool
  subprocesses (`runner.py`, `toolchain.py` version probes) receive only
  `config.tool_environment()`, an allowlist of the Runner's *own* environment (ADR
  0022), so jobs, Map data and tool targets cannot add variables. The allowlist passes
  `LANG`, `LANGUAGE` and `LC_*` through; their values are whatever the image or the
  operator set. Two other subprocess calls (`updates.py`: `pipx upgrade`, an isolated
  `python -I` version probe) inherit the Runner's environment, again its own. `${VAR}`
  references in test cases are refused (`_refuse_environment_references`).
- **Gate:** only a benchmark helper (`bench/main.go`) executes a process; no
  `os.Setenv`/`Clearenv` outside tests.
- **`vardrsec.py runner --env NAME`:** passes only variable names the operator types
  and Compose reads values from the operator's own shell.
- **Database:** SQL cannot set the postmaster's `LANGUAGE`; backends inherit it.
- **Services:** no `openssh`, `sudo` or other environment-forwarding login service in
  any image SBOM, so the reporter's SSH scenario has no equivalent. No Docker socket is
  mounted into any service.

## Impact if the conditions were met

Running as a non-root service account **limits** the impact; it does not remove it.
Capability drop and `no-new-privileges` make privilege escalation inside the container
harder, and setuid helpers ignore `LANGUAGE` (`AT_SECURE`). But code execution as the
service user would still give that user's reach:

- **API:** the database password and `BACKEND_JWT_SECRET` in its environment, and
  full access to the database over the internal network.
- **Web:** `AUTH_SECRET` and `BACKEND_JWT_SECRET`.
- **Runner:** `VARDRMAP_API_KEY` when set, the state volume and the Runner's network
  position (outbound access to authorized targets).
- **Database:** the `postgres` account owns all stored engagement data and evidence.

That is the CVE record's "total" technical impact for the affected process. The
mitigations above reduce the likelihood of reaching that point, not the consequence.
Container isolation, internal networks and the loopback-only published port limit
lateral movement but are not a boundary against these in-process assets.

## Runtime verification (CI run 41221261206, 2026-10-31)

[`tests/glibc_locale_acceptance.py`](../tests/glibc_locale_acceptance.py) runs in the
`installation` job on a clean `ubuntu-24.04` runner after the installed workflow, against
the disposable `vardrsec-compose-review` project. It starts no scan or job, contacts no
target and changes no image, Compose setting or pin. Environments are read in memory and
filtered to locale variable names; no other name or value is printed or stored. The
gettext fixture is a two-string catalog in a throwaway directory. The API's database
password is never read or printed. The job uploads a `glibc-locale-exposure` receipt.

| Image | glibc | Locales | Locale variables | `LANGUAGE` under `C.UTF-8` |
| --- | --- | --- | --- | --- |
| API | 2.41 | `C`, `C.utf8`, `POSIX` | `LANG=C.UTF-8` | Ignored (ordinary and `../xx`) |
| Web | 2.41 | `C`, `C.utf8`, `POSIX` | none | Ignored |
| Runner (one-off container) | 2.41 | `C`, `C.utf8`, `POSIX` | `LANG=C.UTF-8` | Ignored |
| Database | 2.41 | adds `en_US.utf8` | `LANG=en_US.utf8` | Ignored under `C.UTF-8`; **honored under `en_US.utf8`** (positive control) |

The positive control shows the vulnerable behavior is real in this glibc: with a
non-`C` locale selected, `LANGUAGE=../xx` loaded a catalog outside the locale
directory. It also shows the probe would have detected loading in the other images. It
does not show an attacker can set `LANGUAGE` in the database container; nothing found
does.

API database role `vardrmap` (the user in the API's `DATABASE_URL`): superuser,
create-role, create-database and bypass-RLS all **true**. This is the PostgreSQL image's
default for `POSTGRES_USER`. It is outside CVE-2026-84243 but widens the consequence of
any API or SQL compromise (for example `COPY … PROGRAM` runs as `postgres`). It needs a
**separate security review** of a least-privilege application role; no change is made
here, and Map's migrations, which may need owner rights, must be part of that review.

Remaining limits: the probe covers a bash caller and one glibc build (2.41); the Runner
result is for a one-off container of the Compose service, not a running job; nothing
was run under the other base-image variants or the native Runner on a host.

## Options

- **Remediate:** none available. Debian Trixie, bookworm and unstable are unfixed. A
  rebuilt glibc, another base suite or a locally carried patch would break the Trixie
  package policy in [alpha-os-exposure.md](alpha-os-exposure.md) and is not
  recommended.
- **Mitigate:** the existing controls above. **No PostgreSQL locale change and no
  change to the Runner's environment allowlist is proposed here.** Either would change
  behavior in a component and needs its own compatibility verification and PR first.
- **Tracking:** re-scan on each new Debian glibc upload; a fixed version closes the item
  at the next rebuild.

## Proposed conditional exception (not accepted)

If the owner later accepts, it should hold only while all of these remain true:

1. No untrusted party can set a container's environment, and nothing forwards request,
   job or target data into the environment of a glibc program.
2. The API, web and Runner images contain no locale beyond `C`/`C.UTF-8`.
3. No SSH or similar environment-forwarding service is added.
4. It is re-assessed at the first Debian glibc fix, before any published image, and
   whenever conditions 1–3 change.

### Conditions still requiring verification before formal acceptance

| # | Condition | Status |
| --- | --- | --- |
| 1 | API, web and Runner images contain only `C`/`C.UTF-8`/`POSIX` locales | **Runtime-verified** (run 41221261206); re-run at the frozen candidate |
| 2 | No `LANGUAGE`/`LC_*`/`LOCPATH` in any container's environment | **Runtime-verified** for the installed stack and a one-off Runner container; re-run at freeze |
| 3 | `LANGUAGE` is ignored under `C.UTF-8` and honored only where a non-`C` locale exists | **Runtime-verified** with a bash caller and positive control; other callers untested |
| 4 | The API database role is a superuser | **Runtime-verified: true.** Separate security review required; not part of this exception |
| 5 | Upstream advisory text and patch status | Still not read (sourceware.org unreachable) |
| 6 | Whether a target can cause a correctly structured `.mo` file to be written in the Runner state or temp paths | Not investigated; matters only if 1 or 2 stops holding |
| 7 | Native Runner on a host uses that host's glibc, outside Compose | Out of scope here; needs operator guidance in the release notes |
| 8 | Negative source-search findings stay true at the frozen candidate pins | Pins `696a8bf`/`854b973`/`7f82e49` only; repeat at freeze |
| 9 | Owner decision | Pending |

Conditions 1–3 are now evidenced and re-run automatically in the installed acceptance
job, so a regression (an added locale, a locale variable or a catalog loading under
`C.UTF-8`) fails CI. They hold for the shipped images only; they do not remove the
need for items 4–9.
