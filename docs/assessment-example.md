# An ownership defect from reviewed policy to retest

This sanitized example comes from the completed automated Ubuntu 24.04 Full
installation check against a disposable synthetic target. Map held the reviewed
case, evidence, finding and report; Runner explicitly executed Gate. It is not an
unfamiliar-operator trial or an assessment of a production application.

The selected source revisions were distribution `480d4e0`, Map `4a5211c`,
Runner `6b81301` and Gate `2474296`. This records that check; it does not change
the development status or establish release clearance.

## Review the rule before executing

The owner may modify the record. A peer in the same tenant must not modify it.
A third identity, `reader`, independently observes the record before and after
each attempt. All three identities pass their declared principal preflights.

The engagement records the disposable target, written authorization and testing
window. Target credentials establish identities; they do not authorize testing.
The reviewed case explicitly permits mutation, declares synchronous isolated
execution, and resets the record as the owner before each actor. These fixture
guarantees must not be assumed for a real application.

The operator queues the reviewed case in Map and invokes Runner's existing
`jobs run` flow. Queueing alone executes nothing. The ordinary manual workflow
uses advisory scope/window checks and a stop-work refusal; separately enabled
managed execution requires its existing per-job approval controls.

## Compare the response with the verified effect

Both fixture versions return HTTP 204 to both writers. Status alone cannot
establish whether access was correctly denied.

| Target / identity | Reviewed expectation | HTTP response | Independent write verification | Gate's reported decision |
| --- | --- | --- | --- | --- |
| Vulnerable / owner | allow | 204 | `verified_effect` | `allowed` |
| Vulnerable / peer | deny | 204 | `verified_effect` | `allowed` |
| Fixed / owner | allow | 204 | `verified_effect` | `allowed` |
| Fixed / peer | deny | 204 | `verified_no_effect` | `denied` |

Both jobs completed with conclusive assessments and a valid owner baseline. The
vulnerable job produced one candidate finding; the fixed job produced none.
Map's raw `observed_outcome` remains `allow` for the 204 responses, including the
fixed peer. The semantic decision comes from write verification, not that raw
HTTP classification. The separate reader passed preflight, reset returned 204,
and before/after reads returned 200. Response values and credentials are omitted.

The retained case snapshot was verified for both jobs, with the same case hash:
`2d4f757f9009b220aafe67f222b03c625cc734a304615f9af1c96a55dd0771d6`.
This correlates the case and evidence; Runner-reported evidence is not an
independent server attestation.

## Confirm, fix and preserve the original evidence

The automated fixture exercised the explicit reviewer actions: create a triaged
finding for unauthorized modification, link the peer's evidence, and record an
initial retest as `still_open`. It then enabled the disposable target's ownership
check and ran the same reviewed case as a new job. The fixed retest recorded
`verified_fixed` and closed the finding while retaining the original evidence.
These scripted actions do not establish independent human confirmation.

Map exported two delivered report revisions. Revision 1 preserved the open
defect; revision 2 included the remediation and fixed retest. Their content hashes
were respectively
`40340adf7c81bd7ad3d3a5438c382839729965b0c3ad27bb6a10f33af0c72177`
and `a8edacd6b27c507b728c85a4f784631e1fef0b1434f61e1ab6cbc723574bfb13`.
The original report was retained rather than rewritten as if the defect had
never existed. This page omits target addresses, account/job identifiers, raw
response bodies and the private report exports.

An unavailable baseline in the same acceptance check was `inconclusive`, with
zero candidates; that was not a protection pass. This fixture establishes neither
asynchronous completion nor concurrent or cross-service authorization behavior.

## Follow or reproduce the existing workflow

Use the [Full first-assessment instructions](installation.md#first-assessment-walkthrough)
for Map, or the [Mapless instructions](mapless.md) for standalone execution.
For a real retest, review current authorization again and create a new job;
never reuse a spent approval. Follow [recovery and stopping](recovery.md) before
changing retained state. The [managed controls](local-managed-setup.md) apply
when a managed worker was separately enabled.

The existing [write case and lifecycle assertions](../tests/write_lifecycle.py),
[installed acceptance](../tests/gate_acceptance.py) and
[Compose workflow](../.github/workflows/compose.yml) specify the Full reproduction.
That acceptance fixture requires a fresh disposable host: it has fixed resource
names and must not be run against an installation with retained data.

For a small loopback-only reproduction from a Gate checkout containing the
[compact cases](https://github.com/VardrSec/VardrGate/blob/077d59f2e03478505b9b17ca3393c804ba16e4d8/docs/authorization-cases.md), run:

```sh
go test ./cmd/vardrgate -run '^(TestCompactAuthorizationCases|TestSavedRegressionCatchesReintroduction)$' -count=1 -v
```

These existing tests exercise paired vulnerable/fixed cases, credential refusal,
an unsupported write contract, and saved-regression replay through
vulnerable/fixed/reintroduced modes. They do not launch Map or Runner and are not
a substitute for the Full installation check or the pending operator trial.
