# glibc gettext `LANGUAGE` exposure review — CVE-2026-84243, 2026-10-31

**Finding: the vulnerable glibc is present in four images, but no path was found by
which an untrusted party can set the environment of a glibc-gettext program, and the
API, web and Runner images lack the second precondition (a non-`C` locale).** This is
a configuration-specific exposure assessment, not a claim that glibc is patched, a
scanner suppression or an accepted exception. The ten raw occurrences remain, strict
image checking still exits 1, and a conditional acceptance is **proposed only**; the
owner has not decided.

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
discussion and patch merge status were **not read**; the facts above come from the CVE
record and the Debian tracker and bug. Whether upstream has merged a fix is unknown.

## Affected images (confirmed from run 41175264942 raw reports)

All ten occurrences are `affected`, `Unknown` severity, no fixed version, glibc
`2.41-12+deb13u4`: API (`libc6`, `libc-bin`), web (same), Runner (same) and database
(`libc6`, `libc-bin`, `libc-l10n`, `locales`). The Caddy proxy image is Alpine/musl and
has no occurrence; musl was not otherwise assessed.

| Image | Runs as | Image `LANG` | Non-`C` locale installed |
| --- | --- | --- | --- |
| API | 10001 | `C.UTF-8` | No (`locales`/`libc-l10n` absent from the SBOM) |
| Web | `node` | unset | No (same) |
| Runner | 10001 | `C.UTF-8` | No (same) |
| Database | `postgres` after `gosu` | `en_US.utf8` | **Yes** (`locales`, `libc-l10n`) |

## Can an untrusted party influence the environment? Confirmed: no path found

- **Compose** sets no `LANGUAGE`, `LANG`, `LC_*` or `LOCPATH` for any service
  (`compose.yaml`). The only operator-supplied values are the documented ones.
- **Map API** (pin `696a8bf`): no subprocess, `os.putenv` or `os.environ` assignment
  in application code (only in tests), no use of libc gettext; Python's `gettext`
  module is pure Python. HTTP request data cannot reach the process environment.
- **Web** is Node.js; it does not use libc gettext.
- **Runner** (pin `854b973`): every tool subprocess receives only
  `config.tool_environment()`, an allowlist of the Runner's *own* environment (ADR
  0022). Jobs, Map data and tool targets cannot add variables. The allowlist passes
  `LANG`, `LANGUAGE` and `LC_*` through, so the value is whatever the operator or image
  set. `vardrsec.py runner --env NAME` passes only names the operator types. Runner
  also refuses `${VAR}` references in test cases.
- **Database**: PostgreSQL backends inherit the postmaster's environment; SQL cannot set
  `LANGUAGE`. The API's role is the image's `POSTGRES_USER`, which the PostgreSQL image
  creates as a superuser (documented entrypoint behavior, not checked at runtime). A
  party able to run arbitrary SQL already has code execution as `postgres`, so this
  advisory adds nothing for that actor.
- **No environment-forwarding service**: no `openssh`, `sudo` or other login service in
  any SBOM, so the reporter's scenario has no equivalent here.

## Privilege boundary, isolation and file placement

- Even with environment control, the code would run as the same unprivileged user that
  already runs the process. API, web and Runner drop all capabilities and set
  `no-new-privileges`; setuid helpers (`mount`, `su`, `passwd`) ignore `LANGUAGE` under
  `AT_SECURE`. No Docker socket is mounted. Escalation across a boundary is therefore
  not shown.
- The database and application networks are `internal: true`; the only published port
  is the loopback HTTPS proxy.
- A catalog must exist at `<LANGUAGE value>/LC_MESSAGES/<domain>.mo`. Writable locations
  are the Runner state volume and temp space; tools write target-influenced bytes there.
  Whether a target can cause a file with that exact name and structure to be written
  was **not investigated** and is treated as possible. It does not matter without
  environment control.

## Assessment

Exploitation needs three things at once: control over the environment of a program that
calls glibc gettext across a privilege boundary, a selected non-`C` message locale, and
a crafted catalog at a reachable path. In the shipped configuration:

1. No untrusted actor controls any container's environment (confirmed from the sources
   and Compose file above).
2. API, web and Runner cannot select another locale: their images contain only `C`,
   `C.UTF-8` and `POSIX` (inferred from the SBOMs; `locale -a` was not run). The CVE
   record states `LANGUAGE` is ignored in those locales. Behavior was **not tested
   here**; no Linux container runtime was available.
3. Only the database image can honor `LANGUAGE`, and nothing sets it.
4. No privilege is gained: the process already runs as the affected user.

The plausible exposure is in unsupported use: an operator or integrator that forwards
untrusted variables into a container (for example `docker exec` or an SSH-style
`AcceptEnv`), or that adds locales. The native Runner on the host uses the host's glibc,
which this repository does not patch; the Runner allowlist forwards the operator's shell
`LANGUAGE`.

## Remediation and mitigation options

- **Remediate:** none available. Debian Trixie, bookworm and unstable are unfixed. A
  rebuilt glibc, another base suite or an upstream patch carried locally would break the
  Trixie package policy in [alpha-os-exposure.md](alpha-os-exposure.md) and is not
  recommended.
- **Existing mitigations (verified):** no untrusted environment control; capability
  drop and `no-new-privileges`; internal networks; API/web/Runner `C`-locale only.
- **Optional hardening, not applied** (no verified defect, so no code changed): drop
  `LANGUAGE` from the Runner's tool allowlist (a Runner PR); set `LC_ALL=C.UTF-8` on the
  database service. Both are cheap but change behavior in separate repositories or
  Compose and need their own verified PRs.
- **Tracking:** re-scan on each new Debian glibc upload; a fixed version closes the item
  at the next rebuild.

## Recommendation (needs owner decision; nothing accepted)

Propose **conditional acceptance as an alpha limitation**, valid only while all hold:

1. No untrusted party can set a container's environment; nothing forwards variables from
   requests, jobs or targets to glibc programs.
2. The API, web and Runner images install no locale beyond `C`/`C.UTF-8`.
3. No SSH or similar environment-forwarding service is added.
4. Re-assess at the first Debian glibc fix, before any published image, and if
   conditions 1–3 change.

Alternative the owner may choose: require the two optional hardening changes first.
The conditions above are assumptions about the shipped configuration, verified from
sources and SBOMs but not by a runtime test.
