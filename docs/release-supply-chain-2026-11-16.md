# Final source/licensing acceptance — Community Edition v0.1.0 Alpha

**Decision: HOLD for one source-notice delivery correction.** The correction is
prepared in commit `d4504c9` on `codex/alpha-source-evidence-qualification`.
Vigil must include it with the source release; it is not present in the current
candidate or its retained source snapshot. No other specific source-only
licensing defect was identified in the reviewed payload. Overall security and
release approval remain with their owners.

## Exact scope and candidate

[Issue #117](https://github.com/VardrSec/VardrSec/issues/117) identifies RC #116
head `dc8ea493a07d7650961b78d22d3b68690bf62089`: source-built Full and Mapless,
Ubuntu 24.04/amd64, **no prebuilt distribution**. Tested merge
`ee1c06ccc01c20217b8267bccab4f99a4ffbbfa4` has the same complete Git tree.
Pins: Map `76dcbb9d1b17bb06005da86f3f3194e22521bb32`, Runner
`00812c13b4b2986b594fc91712abe7cc96eafea7`, Gate
`2474296597b6ccd082e2e405662fd1f2cada69f4`. Baseline `25040b0` is historical;
its evidence is reused only where the actual inputs remain unchanged.

## Verified source and notice evidence

| Conveyed material | Evidence and result |
|---|---|
| Four complete tracked source trees | Existing source run `44092136381`, artifact `14331838436`, retained all four exact trees. Its existing verifier passes against the expected checksum and tested revision. Reused CI's two-build comparison; no snapshot was rebuilt. |
| Component licenses | Distribution Apache-2.0 plus NOTICE; Map AGPL-3.0, including backend/frontend copies; Runner MIT plus managed-tool notices; Gate Apache-2.0. These remain in the source trees, without blanket relicensing of third parties. |
| Embedded Go sources | The distribution and Runner carry identical source archives with 17 module/version records. All 65 checksum entries and manifest sizes/hashes match; original source ZIPs retain their license/copyright files. Source is delivered for the covered MPL/copyleft material actually included. No compiled dependency is substituted for source. |
| Embedded Dalfox notices/source | Reused the existing integrity review for the unchanged Runner archive, SHA-256 `f51df44eb354eaac6cc7b4b5b695843511471a6d762f885ca4fd8a74a09fc6b5`. It retains legal texts, attribution and four unmodified MPL source crates. The 336-package lock inventory is not 336 conveyed source packages. The Android-only missing grant and Nuclei/Censys notice question do not establish defects in absent source/binary payloads. |
| Four-image ACL source evidence | Complete and reused unchanged: combined run `44092136016`, 220 checksum entries, 24 descriptors, 56 input references, exact image identities. This task is closed; no historical image recovery or rebuild was repeated. |
| Security-source reconciliation | Candidate contains the reviewed Kerberos and libxml2 patches. Compared source artifacts and recipes at the exact candidate; Codex 1 identified no later security-source revision in #117 and reviewed the notice-only correction. No remediation or patch bytes changed. |

Source artifact ZIP SHA-256:
`430bc0a4da99255f150c62a2cfdd6ec0b861f74b9cabe189ea70bdf89c52aea2`.
Inner `source-a.tar.gz` SHA-256:
`ecec33a08e6409705b98df171b1767075e1f82ebd1c1450cf6f3bae41e367192`.
Both were verified locally from the existing
[source artifact](https://github.com/VardrSec/VardrSec/actions/runs/44092136381/artifacts/14331838436).
This artifact proves source identity, but still lacks the correction below.

## Precise remaining requirement and smallest correction

**Source-patch copyright/license notices must accompany the conveyed patch
material.** The current source payload omits, for example, the 2015 MIT and 2016
Red Hat CAMMAC-file notices and the Daniel Veillard 2003–2012 dictionary grant.
Patch author names and upstream URLs do not supply those required notices.
The same review identified affected GNU, ncurses, util-linux, Perl and Go patch
material; this is a source-distribution obligation even without prebuilt images.

Completed correction `d4504c9` adds `NOTICE.source-patches.txt`, mapping all 54
conveyed patch paths across distribution/Map/Runner to 45 affected upstream-file
notice records and eight full referenced license texts. It preserves file-level
exceptions, permissions, disclaimers, attribution and downstream-modification
status. Text came from the retained exact upstream sources; only text encoding,
line endings and trailing whitespace were normalized. Root `NOTICE` points to
it. The existing notice collector recognizes its filename. Patch/build files
are unchanged; `git diff --check` passes. No new tests or packaging system.

**Vigil's required action:** adopt that two-file notice correction into the
source release and ensure recipients receive it alongside all affected patch
files, including the nested Map/Runner trees. If using the existing source
snapshot, package the changed source payload with `source_release.py` and retain
its new revision/checksum. Reuse unchanged component and qualification evidence.
This is source packaging after changed notice input, not an image-rebuild request.
The source-license hold closes when the corrected delivered payload is identified
and its notice inclusion is verified. Do not publish the uncorrected snapshot as
if it already contains the notice. No permission to publish is implied.

## Boundaries and handoff

Base-image notices, complete OS/wheel binary source delivery, binary relinking
materials and registry image pins are not automatic blockers for this explicitly
source-only release. They require reassessment if prebuilt distribution is added.
Missing scanner metadata, development manifest flags, non-regular library aliases
and absent historical images are not additional licensing requirements here.
No general source-offer service, signatures or byte-identical image rebuilds are
required by this report. Security adjudication stays with Codex 1/Vigil; public
release-note/archive hygiene stays with its assigned documentation owner.

Detailed local evidence: `final-source-rc116/source-only-review.json`,
`verified-manifest.json` and `notice-correction-provenance.json`; existing ACL
acceptance remains in `combined-rc116-44092136016/acl-source-verification.json`.
