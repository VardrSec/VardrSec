# Final source/licensing acceptance — Community Edition v0.1.0 Alpha

**Source/licensing technical acceptance: PASS for the notice-corrected source
payload identified below.** Notice correction `d4504c9` is adopted in prepared
source candidate `4f3e813218baf9f14e8238fbaf8875392d6db1ab`, exactly the prior
RC plus two notice files. The resulting archive passes the existing verifier
and explicit notice-inclusion checks. Vigil's official RC/source-payload
selection remains pending; PR #116 still records `dc8ea493`. No unresolved
source-only licensing defect was identified in the corrected payload.
Overall security and release approval remain with their owners.

## Exact scope and candidate

[Issue #117](https://github.com/VardrSec/VardrSec/issues/117) identifies RC #116
head `dc8ea493a07d7650961b78d22d3b68690bf62089`: source-built Full and Mapless,
Ubuntu 24.04/amd64, **no prebuilt distribution**. Tested merge
`ee1c06ccc01c20217b8267bccab4f99a4ffbbfa4` has the same complete Git tree.
The notice-only source candidate is on `codex/rc116-source-notices`; its only
changes from that RC are `NOTICE` and `NOTICE.source-patches.txt`.
Pins: Map `76dcbb9d1b17bb06005da86f3f3194e22521bb32`, Runner
`00812c13b4b2986b594fc91712abe7cc96eafea7`, Gate
`2474296597b6ccd082e2e405662fd1f2cada69f4`. Baseline `25040b0` is historical;
its evidence is reused only where the actual inputs remain unchanged.

## Verified source and notice evidence

| Conveyed material | Evidence and result |
|---|---|
| Four complete tracked source trees | Existing source run `44092136381`, artifact `14331838436`, proves the parent source trees. Packaged the changed notice input once with existing `source_release.py`; its verifier passes for `4f3e813`. All three component archive hashes remain identical to that verified parent artifact. |
| Component licenses | Distribution Apache-2.0 plus NOTICE; Map AGPL-3.0, including backend/frontend copies; Runner MIT plus managed-tool notices; Gate Apache-2.0. These remain in the source trees, without blanket relicensing of third parties. |
| Embedded Go sources | The distribution and Runner carry identical source archives with 17 module/version records. All 65 checksum entries and manifest sizes/hashes match; original source ZIPs retain their license/copyright files. Source is delivered for the covered MPL/copyleft material actually included. No compiled dependency is substituted for source. |
| Embedded Dalfox notices/source | Reused the existing integrity review for the unchanged Runner archive, SHA-256 `f51df44eb354eaac6cc7b4b5b695843511471a6d762f885ca4fd8a74a09fc6b5`. It retains legal texts, attribution and four unmodified MPL source crates. The 336-package lock inventory is not 336 conveyed source packages. The Android-only missing grant and Nuclei/Censys notice question do not establish defects in absent source/binary payloads. |
| Four-image ACL source evidence | Complete and reused unchanged: combined run `44092136016`, 220 checksum entries, 24 descriptors, 56 input references, exact image identities. This task is closed; no historical image recovery or rebuild was repeated. |
| Security-source reconciliation | Candidate contains the reviewed Kerberos and libxml2 patches. Compared source artifacts and recipes at the exact candidate; Codex 1 identified no later security-source revision in #117 and reviewed the notice-only correction. No remediation or patch bytes changed. |

**Corrected source archive:** `notice-adoption-delivery/source-a.tar.gz`,
source commit `4f3e813218baf9f14e8238fbaf8875392d6db1ab`, SHA-256
`4322d2744b3f1007a852974bd6d975360505b52e4bd25287f4ead3b65555a252`.
The notice SHA-256
`7350e11e82f53c17f0a935eae4a6c56563fcae946bb079125bcf82ae9ffda607`
matches the committed correction, the outer collected notice and the copy in
`distribution/source.tar`; root `NOTICE` references it. The three component pins
and source archive hashes are unchanged. Only the source archive was packaged;
no images were rebuilt and no qualification was rerun.

The previous CI source archive, SHA-256
`ecec33a08e6409705b98df171b1767075e1f82ebd1c1450cf6f3bae41e367192`,
is retained as parent evidence and must not be described as notice-corrected.

## Notice correction and adoption handoff

**Source-patch copyright/license notices must accompany the conveyed patch
material.** The parent source payload omitted, for example, the 2015 MIT and 2016
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

**Vigil's remaining action:** select the prepared notice-corrected candidate
and verified archive as the recipient source payload, or identify an alternative
official adoption revision so its source identity can be rebound. The correction,
archive checksum and inclusion evidence were sent to Vigil in the existing
coordination chat. No official tag, artifact publication, baseline advance or
RC #116 branch update was made independently. The official candidate record
must distinguish the original RC from this verified notice-corrected payload.

For this exact corrected archive, the source-notice delivery defect is resolved.
Recipients must receive that archive or an equivalently verified source payload
with the notice alongside the affected distribution/Map/Runner patches. Keep
existing image/security receipts at their original identities; no image rebuild
is needed for this notice-only source delivery.

## Boundaries and handoff

Base-image notices, complete OS/wheel binary source delivery, binary relinking
materials and registry image pins are not automatic blockers for this explicitly
source-only release. They require reassessment if prebuilt distribution is added.
Missing scanner metadata, development manifest flags, non-regular library aliases
and absent historical images are not additional licensing requirements here.
No general source-offer service, signatures or byte-identical image rebuilds are
required by this report. Security adjudication stays with Codex 1/Vigil; public
release-note/archive hygiene stays with its assigned documentation owner.

Detailed local inclusion evidence: `notice-adoption-delivery/notice-inclusion-verification.json`
and `SHA256SUMS`. Original source audit: `final-source-rc116/source-only-review.json`,
`verified-manifest.json` and `notice-correction-provenance.json`; existing ACL
acceptance remains in `combined-rc116-44092136016/acl-source-verification.json`.
