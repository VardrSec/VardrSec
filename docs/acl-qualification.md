# Bounded ACL cohort qualification

This describes the test-only ACL cohort for distribution PR #114. It is not a
release declaration, a production override, or permission to merge or publish.
The committed `versions.json` remains authoritative for ordinary installations
and source snapshots. Component checks alone do not establish aggregate closure.

## Reviewed inputs

The companion revisions selected by the cohort are:

| Component | Distribution pin | Reviewed companion head |
| --- | --- | --- |
| Map | `4a5211c2bcef5b89ba3d8a12244c3acffb55f188` | PR #167: `90595da2b5e1eeff4112dde1802ee637b9b972bb` |
| Runner | `f57ea3a95dd01837043eaf61a54cb2f73d9ab265` | PR #137: `6d24206734ee6efa39bee2494428d4ebce857c3a` |

Map's companion base is `a73a988dbbbab7d07e90dc8cf67212200162e1d5`, not the
distribution pin. Runner's companion base equals its distribution pin. The
fixture selects the exact reviewed companion heads, including the separately
reviewed Map history between its distribution pin and companion base. The
production manifest is not advanced. Gate remains at
`2474296597b6ccd082e2e405662fd1f2cada69f4`.

The triggering distribution head, reviewed database identity, component delta
hashes, permitted paths and production-manifest hash are checked by
`tests/acl_cohort_acceptance.py`. Consult that exact revision and its retained
receipt rather than treating this document as a database qualification result.
Changing any reviewed input requires review and a fresh qualification; an older
successful run cannot qualify a changed head.

## Preparation and refusal boundaries

The `acl-cohort` job in `.github/workflows/compose.yml` runs only for same-repository
PR #114 on `codex/acl-caller-security`, on a fresh GitHub-hosted Ubuntu 24.04 VM.
It refuses source, Compose, Docker and Git configuration overrides, dirty source
checkouts, external Git metadata, existing installation state, pre-existing
fixture/evidence directories and changed production pins.

Preparation verifies separate exact hashes and path allowlists for the reviewed
pin-to-base history and ACL delta. It applies the ACL delta to the companion base,
checks file modes/types/blobs and the complete resulting tree against the reviewed
head, then checks out that actual head. Map history is limited to `.gitignore`,
`CHANGELOG.md`, backend requirements and frontend package manifests; Runner has
no intervening history. The version-2 receipt records selected commits and trees.
Only the isolated distribution fixture gets a synthetic manifest commit selecting
these exact companion heads. The original manifest remains unchanged and existing
source guards run without bypasses. No synthetic component commits are selected.

The job then uses the existing installation and joint acceptance paths. Before
smoke it records built images and frozen image selection. Verification checks
that source identities, manifest bytes, image aliases, image IDs and frozen
selection remain unchanged, and binds the running stack to the tested images.
The existing joint acceptance receipt must be present.

## Source, regression and installed-payload controls

For database, API, web and Runner images, the runtime check runs without network,
with capabilities dropped and no-new-privileges, retaining each image's configured
runtime user. It verifies the retained source manifest under
`/usr/share/doc/libacl1/vardr-source/`. Public source inputs must therefore be
readable by that runtime user without privilege escalation; overriding the image
user or restoring dropped capabilities is not a substitute.

The retained build evidence must contain both stock cp/tar
`EXPECTED_VULNERABLE` witnesses and both stripped fixed-payload `PASS` witnesses.
The builder keeps ordinary ACL preservation, special-file/FIFO and intended
symlink controls, five top-level coreutils ACL tests and six native gnulib ACL
tests. A stock setup failure is not a vulnerability witness. These are bounded
regressions, not a claim of universal filesystem race protection or complete CVE
coverage.

Finally, the runtime check selects exactly three hashes from the retained binary
package manifests: installed cp, tar and libacl. It verifies these from `/`.
This binds the build evidence to actual runtime bytes and detects a later layer
replacing a tested payload. Merely retaining a successful build log is insufficient.

## Reading results and rerunning

The workflow uploads `acl-cohort-public-evidence` with 30-day retention, including
sanitized `provenance.json` and each service's `-acl.log`, `-acl.stderr.log` and
`-acl.result.json`. It does not upload private installation state or credentials.

Receipt states distinguish progress from qualification:

- `prepared-not-qualified`: identities prepared; no aggregate result.
- `built-not-qualified`: images recorded; no aggregate result.
- `FAIL`: runtime evidence was collected but at least one required runtime failed.
- `PASS`: all four required runtime checks succeeded after the joint and identity
  checks. Inspect the exact distribution head, component identities and run attempt.

An earlier guard/build/smoke failure can leave an intermediate receipt or prevent
receipt creation. Missing evidence or an uploaded artifact is never itself PASS.
Successful joint smoke with a failed ACL verdict remains unqualified.

For an unchanged head, open its PR #114 Actions run, verify the full head SHA and
choose **Re-run failed jobs** after the workflow has finished. Inspect the new attempt's
`acl-cohort` job and artifact. For a changed input, review the change and use the
new head's pull-request run; rerunning an old run still tests the old head. Do not
invoke the helper locally, spoof its event environment, change pins to satisfy a
guard, or reuse an old fixture. The helper deliberately refuses those shortcuts.
This PR-only job is not an enduring main-branch or release qualification gate.

## From a test cohort to a shipping candidate

The current test candidate includes the reviewed newer Map base, retaining its
dependency/security updates rather than maintaining an older-base ACL backport.
The previous pinned-base-only result at distribution `18695ecb` does not qualify
this newer cohort. Qualification requires a new run and its version-2 receipt.
The exact selected companion commits are test inputs, not approved permanent pins.

After selecting the route, component merge approvals and permanent distribution
pin/merge approvals remain separate. Retest the exact resulting shipping cohort;
merge outcomes or new pins must not inherit qualification by assumption. Keep
production pins unchanged until approved. Source/license, publication and
deployment gates remain separate, and Community publication remains on hold.
