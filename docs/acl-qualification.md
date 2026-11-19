# Full installation ACL checks

The Full installation job records the database, API, web and Runner image IDs
before the joint smoke test. After smoke it verifies the image identities and
checks the installed `cp`, `tar` and `libacl` bytes against the package
manifests in all four images. Qualification of a candidate requires a passing
job for that revision. Inspect the per-image output and exit codes alongside the
joint acceptance receipt. [Compose acceptance](../.github/workflows/compose.yml)

## Historical qualification

PR #114 qualified a fixed test cohort at distribution commit `2bc4ce2`.
Git retains the harness and original runbook at that commit. The successful job
uploaded its evidence with 30-day retention. [Original runbook](https://github.com/VardrSec/VardrSec/blob/2bc4ce2b552bbd4509ee11645ab87ea33ad0fc37/docs/acl-qualification.md) · [Qualification job](https://github.com/VardrSec/VardrSec/actions/runs/43835515930/job/133191042086)
