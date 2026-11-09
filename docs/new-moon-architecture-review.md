# New Moon architecture overview — review draft

This records implemented boundaries, measured evidence and remaining NM-5 gates.
It is not architectural signoff, release approval or a proposal for another initiative.

The accepted source-built NM-4 cohort is distribution `b4133d7`, Map `c983a60`,
Runner `dec2ac6` and Gate `57cfedf`. Receipts retain their full commits and hashes.
The runtime-security cohort is now qualified at distribution `700e003` (PR79),
Map `55458b7`, Runner `519c047` and unchanged Gate `57cfedf`. Its tree equals
reviewed head `b3fb937`; all required existing checks passed. Rebuilt evidence
verifies 16 high and four medium occurrences removed, with no added findings.
Remaining raw totals are 1 critical/207 high/8 unknown; every image risk gate
remains blocked. This is source compatibility evidence, not release approval.

## Component boundaries

| Component | Responsibility |
| --- | --- |
| VardrMap | Research interface, engagements, reviewed policy/cases, queue proposals, authorization issuance, budgets, findings, evidence and reports. |
| VardrRunner | One execution engine: local workspaces, shared contract validation, local credential resolution, controlled execution, durable journal, result transport and redacted export. |
| VardrGate | Independent multi-identity API authorization assessment, setup/preflight and evidence-backed classifications. Runner invokes its existing CLI/JSON contract. |
| VardrSec distribution | Exact component pins, Full/Mapless Compose installation, lifecycle, HTTPS/trust, controlled updates, backup and recovery. |
| VardrLab | Independent benchmark scenarios and oracle metadata; it does not authorize jobs or replace Gate's assessment engine. |

Full connects Runner to Map through HTTP. Mapless needs neither Map nor an account/API key.
Both retain the same execution and authorization groundwork. Separate installations
preserve original Mapless history; automatic conversion/import/synchronization is deferred.

## Safety invariants

- Normal installation/startup is inert. The managed worker requires explicit opt-in;
  persistent availability grants no job authority. Every job needs fresh valid authority.
- Shared contracts bind issuer, origin, operations, scope, expiry and constraints.
  Existing manual CLI paths retain their documented compatibility and advisory semantics.
- Credentials resolve locally under engagement/origin grants. Map stores references;
  result/provenance metadata is redacted and is not cryptographic attestation.
- Native deadlines, cancellation, budgets and physical completion govern execution.
  Unknown claim/upload/finish outcomes hold; recovery never manufactures missing ACKs.
- Ordinary containers retain least privilege and no Docker socket. The approved worker
  bootstrap is separate; its owner/Runner UIDs and all five empty steady-state capability
  sets remain required. The protected host stop credential stays outside worker mounts.
- Receipts and original evidence survive stop/recovery. A completed job does not prove
  conclusive policy coverage, independent reproduction or absence of vulnerabilities.

## Measured Windows and Linux evidence

PapaChin Windows 11/Docker Desktop records establish fresh application installations
with preinstalled prerequisites, distinct projects/state and preserved existing resources.
Canonical Full/Mapless installation and recovery retained CA-verified readiness,
database/volume fingerprints and byte-identical Mapless re-exports; no OS reinstall is claimed.
Windows Full research workflows, service restart and state-preserving Mapless update
are reusable within their recorded commits. Native CA enroll/accept/remove/reject also passed.

Ubuntu Full/Mapless installation, controlled execution/export, recovery, failed-update
handling and trust renewal passed existing CI. Final NM-4 Windows/Linux component and
installed compatibility checks passed; source changes must remain tied to their own receipts.
Accepted standalone Recon is finite DNS-A → original HTTPS/443 GET-root only.
Its Windows receipt observed one DNS question and one HTTPS response, with unchanged re-export.

NM-2 C01–C08 have credit within their fixed recorded scopes. C09 remains unaccepted;
manual fault/sleep testing stays stopped. C10 source review is done; final disposition is pending.
Native Windows export retains its documented 24H2+/local-NTFS boundary. No integrated native
Full stack, raw-packet container support, broad Recon or genuine VPN certification is inferred.

## Removed debt and retained limits

Merged work provides independent workspaces, shared issuance/validation, private issuer
custody, controlled finite Recon, portable evidence, mode-aware recovery and Mapless updates.
NM-4 adds operation × identity × boundary visibility, grounded drafts, operator-approved
queue proposals, scoped local MCP reads and redacted execution context without a second engine.
Offline exact-pin component notice/source collection now records Git objects and
archive hashes without fetching; full transitive/source-delivery review remains open.
Lab reports retain sanitized observations and source/result hashes; existing CI
retains those receipts without duplicate branch-push/PR runs.
Unsupported dynamic capture/substitution, general cleanup/token lifecycle and missing
workflow facts remain explicit rather than being counted as successful assessment.
Dependencies still resolve during source builds; source-built compatibility is not a release artifact.

## Six remaining closure gates

1. **Frozen-cohort attribution:** compose retained Full/Mapless evidence with exact final
   pins/input hashes and affected rebuilt-image/compatibility results; preserve Windows priority and Linux coverage.
2. **Persistence/offboarding:** record explicit host/Docker restart persistence. Reuse existing
   service-restart, recovery and exact native CA-removal proof; do not substitute one boundary for another.
3. **Network support:** finish required authorized route/native-fallback qualification or
   explicitly exclude unsupported routes. VPN, split-DNS and reconnect are not proved by synthetic reachability.
4. **Independent validation:** finish auditable benchmark classifications/comparable opportunities
   and timed unfamiliar-user acceptance; the owner will perform guided owner acceptance,
   recorded separately. Installed positive cases alone do not establish research efficacy.
5. **Risk/artifact review:** verify fixes, current SBOM/transitive licensing/source delivery,
   candidate artifact reproduction and owner/expiry dispositions. Run 42543020270 retained
   1 critical/223 high/8 unknown occurrences. The matched remediation run 42548636107
   records 1 critical/207 high/8 unknown, with all 16 fixable highs removed; every image gate remains blocked.
6. **Final architectural/safety disposition:** resolve the existing phase decision and signoff
   with C09's unaccepted result unchanged. No stopped testing resumes and no new initiative is proposed here.

Basis: original New Moon roadmap NM-5 scope/exit (lines 175–188), the New Moon acceptance
ledger, NM-2 fixed checklist/evidence, platform/network/trust documents and residual-risk register.
Offline notice/source-archive aids do not establish complete source delivery or license compliance.
NM-5 remains open; publication, deployment and release authorization remain separate owner decisions.
