# NM-1 closeout evidence

Status: closeout draft; NM-1 is not declared complete by this document. Actual
Windows Desktop Gate/network feasibility proof and final review remain pending.

The original New Moon charter is unchanged. NM-1 establishes common permission
semantics and an early deployment decision. Complete Full/Mapless installation,
managed-worker execution, fresh-host certification and the final network/recovery
matrix belong to their later gates. They are not removed from New Moon.

## Sources under review

- Runner base `b8ecb5b378365c51099d5f19b809c9cbb908a094`; its authorization
  implementation matches the verified `440ebda` source. Closeout adds proof only.
- Map `aad63c8151789cd9bf56864456b5fdf1fdcfde41`; its read-only
  `backend/nm1_authorization.py` adapter and ADR 0005 remain unchanged.
- Gate `54536ea1d900d0e35adf93b4e026962c4d45d34a` is the corrected cohort used
  by the existing native guarded-execution and Full evidence.
- Distribution closeout follows `41bca70`; production component pins remain
  unchanged. The historical `.github/nm1-sources.json` selects an older cohort,
  so its workflow is not treated as current-source closeout evidence.

Final proof receipts must identify the actual source revisions and changed test
bytes. A base commit or a test count alone is not phase acceptance.

## Charter exit matrix

| Original exit requirement | Existing implementation/evidence | Closeout disposition |
| --- | --- | --- |
| Contract specification and threat model reviewed | Runner ADR 0025, `docs/contracts` schemas/threat model, and Map ADR 0005 define issuer/purpose/origin trust, reviewed authority snapshots, exact plans, offline limits, replay/fences and compatibility. | Final independent review must record the current documents, limitations and disposition. No new policy or signing service is required. |
| Reference validator passes positive and negative fixtures | Runner authorization contract, CLI, document and runtime tests cover forged/tampered permission, binding/scope/time, revoked authority, trust/purpose, plan/auxiliary requests, replay and conservative durable state. | Focused proof passed, including direct signed future-schema and envelope-version denials; each denial leaves the contract unconsumed. |
| Map and standalone prototypes issue semantically equivalent contracts | The read-only Map owner-session projection supplies reviewed facts; both origins use the same Runner approval/issuance/validation implementation. [The cohort harness](../tests/nm1_contract_acceptance.py) exercises bounded reuse, single-use consumption and denied API-key approval. | Explicit normalized approval/contract comparisons passed. Only issuer/origin, their bound approval digest, and the required local-offline versus managed-online control distinction may differ. Managed control is fixture-injected, not a production worker. |
| Legacy paths still pass CI | Existing Runner cross-platform regression and exact-cohort Linux Full installation/assessment/recovery evidence remain available. Map denies legacy claim/result/control paths for jobs requiring managed contracts. | Reconcile current-source CI and focused compatibility evidence. Do not substitute Full installation success for contract/worker assurance. |
| Explicit migration/rollback | NM-1 adds opt-in journal tables and an unregistered read-only Map adapter. Existing engagements, case hashes, CLI/queue and evidence semantics are preserved. Runner ADR 0025 and Map ADR 0005 describe rollback. | Keep prototype journals and spent IDs/ordinals for audit; disable/remove the opt-in path without deleting state or treating required contracts as legacy permission. NM-2 migrations are a separate review. |
| Windows Desktop feasibility report and approved deployment path/fallbacks | [The measured Desktop trial](nm3-windows-desktop-feasibility.md) built the real toolkit, demonstrated trusted container-to-Map diagnostics, stopped the owned project with state retained, and preserved offline workspace metadata. Native fixed-Gate execution has a separate fourteen-dispatch proof. | Actual Desktop Gate/network proof and the go/no-go deployment decision remain pending. Preserve Windows-first/Docker-preferred/native-compatible direction; do not infer a Docker-only deployment or supported VPN/private modes. |

## Focused contract proof

The current working-source proof passed 153 Runner authorization/compatibility
cases, with one expected Windows FIFO skip, and 33 Map projection/legacy-denial
cases without skips. The existing cohort harness passed explicit normalized
approval/contract equality across standalone and Map origins, bounded approval
reuse, single-use consumption and excess-count refusal. Its normalized permission
digest is `20c82ec8b7de765b9cec94d3786ef489d005606d5562765dd72ede28a69fb0ec`.
All traffic and authority were synthetic; the cohort proof made zero network
requests. No runtime or production policy changed.

These are focused assertion results, not a new whole-project coverage result.
The Map invocation used a protected temporary working directory; its existing
relative coverage configuration reported no data. Full coverage thresholds remain
unchanged. An initial Map collection attempt refused an absolute test-database
URL; the successful run respected the existing disposable-name guard using a
relative `vardrmap_test*` database in that temporary directory.

## Feasibility boundaries

The early charter scope includes toolkit execution, API communication, trust,
persisted artifacts, stop/restart, resource demand and representative routes.
It permits a report of limitations and approved native fallbacks. It does not
permit silently replacing required Docker behavior with native-only support.

Only controlled synthetic loopback/host targets are authorized for the closeout.
Public/customer and real VPN targets are not authorized. An unavailable route
must be labelled unverified, with the required later proof retained. Existing
private-target, TLS and tool-capability controls remain enabled; no Docker socket,
privileged container or host credential-store exposure is introduced.

The current native fixed-Gate proof supports that bounded profile only. It does
not establish general native VPN compatibility, raw-packet support or containment
for arbitrary tools. Linux controlled execution and the approved managed worker
remain NM-2 requirements. Full/Mapless installer and final Windows acceptance
remain NM-3/NM-5 requirements.

## Completion still required

Record the focused proof receipts, current-source legacy CI, independent
specification/threat-model review, actual Desktop Gate/network outcome and a
specific deployment/fallback decision. Update the phase disposition only after
those requirements have been reviewed. Preserve earlier passing and refused
receipts separately; the stopped Windows recovery extension is not NM-1 proof.
