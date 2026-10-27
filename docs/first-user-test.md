# First-user test protocol (Community Alpha task 9)

Developer automation cannot establish this result. The clean-Ubuntu CI run starts
with Python, Git and Docker already installed and follows a script; this test uses a
researcher who has never seen the project.

## Setup

- A fresh Ubuntu 24.04 amd64 machine or VM with no Docker, Git or project files.
- The tester receives only the [installation guide](installation.md) and the
  controlled example target the observer provides. No chat help unless the tester
  is stuck for more than ten minutes; every intervention is logged.
- Use a disposable target that the observer owns. Do not test anything external.
- The observer records, and does not narrate. Screen recording is optional and must
  not capture credentials.

## Task for the tester

Install the platform, create a local account, create an engagement with a client,
scope and written authorization, add two identities, review and queue an
authorization test case, run it explicitly, read the evidence, confirm a finding,
and export a report.

## Record (one row per step)

| Step | Start | End | Completed unaided | Error or confusion (verbatim) | Intervention |
| --- | --- | --- | --- | --- | --- |
| Prerequisites (Docker, Git, Python) | | | | | |
| Acquire and configure | | | | | |
| Build and start | | | | | |
| Trust the local CA | | | | | |
| Bootstrap account and sign in | | | | | |
| Runner key and connection | | | | | |
| Engagement, client, scope, authorization | | | | | |
| Identities and reviewed case | | | | | |
| Explicit run and evidence | | | | | |
| Finding confirmation and report export | | | | | |

## Outputs

Total time from first command to exported report, number of interventions, the
first point the tester could not proceed alone, and every message the tester found
misleading. Each failure becomes a tracked issue; a documentation fix and a product
fix are recorded separately. Raw notes stay out of the repository if they contain
credentials or target details.
