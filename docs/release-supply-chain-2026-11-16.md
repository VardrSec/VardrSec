# Final source/licensing acceptance - Community Edition v0.1.0 Alpha

**PASS for RC #116 revision `2dc5f5133ffdc026ed2c1ddb83471e6a0608c460`
and the exact source archive below.** The notice correction is adopted and its
inclusion independently verified. No mandatory source/licensing blocker remains
identified in this reviewed source-only payload. This is not overall release or
security approval, and no official artifact publication was performed.

## Scope and exact deliverable

[Issue #117](https://github.com/VardrSec/VardrSec/issues/117) defines source-built
Full and Mapless on Ubuntu 24.04/amd64, with no prebuilt distribution.
[RC #116](https://github.com/VardrSec/VardrSec/pull/116) now has the accepted
source revision above; the [superseding Vigil handoff](https://github.com/VardrSec/VardrSec/issues/117#issuecomment-6960213611)
records the same revision and archive identity.

- Archive: `notice-corrected-rc116/source-final.tar.gz`.
- SHA-256: `95d7b9f27cb29028e91b256221f54de0823fe739be77926a087e647e82cd59cb`.
- Notice SHA-256: `bd8fcbc39e4ea2cf2593f207678877637b66adcf3728ecfb5c4698688075e93c`.
- Pins: Map `76dcbb9d1b17bb06005da86f3f3194e22521bb32`, Runner
  `00812c13b4b2986b594fc91712abe7cc96eafea7`, Gate
  `2474296597b6ccd082e2e405662fd1f2cada69f4`.

Only `NOTICE` and `NOTICE.source-patches.txt` differ from the qualified code
candidate `dc8ea493`. Security patches, build recipes, workflows and pins are
unchanged. The final Git tree equals reviewed source candidate `76a9b37`.
Existing qualification receipts retain their original image identities.

## Verified mandatory evidence

| Conveyed material / obligation | Result and evidence |
|---|---|
| Exact corresponding source | Existing `source_release.py verify` passes against the final revision and expected archive checksum. All four complete tracked source-tree archive hashes equal the independently reviewed payload. Reused the owner's two-byte-identical-source-build result; no verification rebuild. |
| Component licenses | Distribution Apache-2.0 and NOTICE; Map AGPL-3.0, including backend/frontend copies; Runner MIT and managed-tool notices; Gate Apache-2.0 remain delivered. Third-party material retains its own terms. |
| Actual embedded Go sources | Two identical source archives retain 17 module/version records. Prior bounded review verified all 65 checksum entries and manifest sizes/hashes; original legal files remain inside each unmodified source ZIP. Full source is conveyed for the MPL/copyleft material actually present. This evidence is reused unchanged. |
| Actual embedded crate sources | Unchanged Dalfox legal/source archive retains legal texts, attribution and four unmodified MPL source crates. Existing 217-entry archive integrity evidence is reused. The 336-package lock inventory does not mean 336 source packages are conveyed. Absent Android/Censys code or binaries are not invented redistribution blockers. |
| Source-patch notices | Correction `d4504c9`, followed by the four-line UTF-8 attribution repair, maps 54 conveyed patch paths across distribution/Map/Runner to 45 affected upstream-file notice records and eight full referenced license texts. Root NOTICE points to it; original permissions, disclaimers, exceptions and modification status are preserved. |
| Notice delivery in final archive | Exact corrected notice bytes match both `distribution/NOTICE.source-patches.txt` in the outer collector payload and the copy inside `distribution/source.tar`. The inner root NOTICE references it. Original accented author spellings are verified. |
| Accepted ACL evidence | Four-image ACL source-delivery task remains complete on combined run `44092136016`: 220 checksum entries, 24 source descriptors and 56 input references, bound to their exact images. No repeat recovery, rebuild or qualification. |

The source-patch correction preserves, among others, MIT's 2015 and Red Hat's
2016 CAMMAC file notices, Daniel Veillard's dictionary grant, GNU and util-linux
terms, ncurses attribution, Perl alternatives and Go-source notices. Codex 1
reviewed the notice-only scope; no owned remediation was changed.

## Acceptance boundary and delivery instruction

Deliver the identified final archive, or an equivalently verified source payload
with the notice accompanying all affected distribution/Map/Runner patches.
The earlier `ecec33a0...` uncorrected CI archive and the intermediate prepared
archives are superseded and must not be labeled as this accepted payload.
The current corrected source archive satisfies the source-notice condition.

No remaining source/licensing owner decision is required for this exact payload.
Vigil retains overall release approval and official publication. Security
adjudication remains with Codex 1/Vigil. Prebuilt-image redistribution, binary
relinking material and additional OS/wheel source obligations must be reassessed
if that separate distribution scope is introduced; they are not blockers for the
source-only payload reviewed here. Expected collector limitations and manifest
flags add no acceptance requirement.

No images were rebuilt, workflows rerun, generalized system added or new test
suite written. Detailed final proof is retained in
`notice-corrected-rc116/codex2-final-source-acceptance.json` and its paired
`verified-final-manifest.json` / `SHA256SUMS`. Original source review remains in
`final-source-rc116/source-only-review.json` and notice provenance beside it.
