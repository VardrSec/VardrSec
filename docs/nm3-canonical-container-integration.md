# Recovery container-selection reconciliation

Base: `07307a2707eefd772f00eeac6d4977680f854c4d`.
Historical verified cohort: `f289a0ce378b9fce382fdaa50a9cc09d4a73f2d4`.
Their common ancestor is `523c69657928c83bb203f738343da8d96ddb4402`.
Neither development line is treated as already merged into the other.

The existing fix originates in
`7a86b83b2a60e8825d57b679e54df94a75af692b` and is present unchanged in the
historical cohort. Apply its recovery.py change verbatim and reuse its four
`test_service_lookup_*` methods. The historical commit also changes unrelated
workflow/upgrade-fixture files, so it is not cherry-picked wholesale. The focused
patch applied without conflicts; no ancestor or unrelated component is replayed.

Canonical selection inspects every Compose-returned container. All candidates
must carry a recognized oneoff label and the expected service label; when a
project is explicit it must also match. Classified one-offs are excluded. Exactly
one canonical service is required. Unknown metadata, foreign candidates, zero
canonical containers and multiple canonical containers fail closed. With no
explicit project, selection continues to rely on Compose's project resolution,
exactly as the established fix does. No broader identity or race-resistance claim.

The version-aware snapshot helper and v1–v4 validation/cancellation behavior from
07307a2 are retained. No pins, role logic, backup format, installer, Compose files,
architecture or actual environment is changed.

Validation: 12 focused recovery tests passed. Full existing suite: 162 run,
158 passed, 4 skipped because official age tools are unavailable. Tests use
synthetic fixtures and mocked Docker boundaries; no live daemon or user state.
Historical test bodies and production selection match the established fix.

Run 41730266134 remains evidence only for historical f289a0c: actual Community
0031→0038 migration, not a test of this new integration. Existing NM-3 hosted
fresh/recovery/update results keep their original exact heads as well. No repeated
migration run or new hosted execution is claimed here.

Independent review of the final integration precedes any publication. Final
exact-head installed upgrade, nonempty managed-state retention, final NM-3 cohort,
Mapless-to-Full/no-loss, encrypted recovery, Windows, SQLite snapshot non-mutation
and journal replacement-race gates remain open. Recon and managed Docker execution
remain disabled; the failed watchdog-hang gate is unaffected.
