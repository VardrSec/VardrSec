# First-user test protocol (Community Alpha task 9)

This original NM-5 gate needs a researcher unfamiliar with the project. Reuse
developer installation/workflow evidence separately; record only what this person
actually completes. This protocol is not permission to publish or run fault tests.

## Setup

- Primary target: Windows 11 with Docker Desktop Linux containers, using clean
  application checkouts and new project/state. Record preinstalled Docker, Git and
  Python prerequisites; an OS reinstall is not required. Ubuntu 24.04 may supply
  additional Linux evidence and does not replace the Windows target.
- The tester receives the [mode selection](../README.md#install-docker-and-compose-python-310-git),
  [Full installation guide](installation.md), [Mapless walkthrough](mapless.md) and the
  controlled example target the observer provides. No chat help unless the tester
  is stuck for more than ten minutes; every intervention is logged.
- Use a disposable target that the observer owns. Do not test anything external.
- The observer records, and does not narrate. Screen recording is optional and must
  not capture credentials.

## Owner acceptance

The owner may perform the same walkthrough with guided assistance. Record that
session as owner acceptance, including all assistance and actual mode-specific
results. It does not silently replace independent unfamiliar-user evidence.
For this owner session, attempt Full first and Mapless in a separate checkout;
keep existing installations and their state intact.

## Task for the tester

Record the selected mode and candidate commit before starting. For Full: install,
create a local account and engagement with client/scope/written authorization,
review identities and a case, queue it, explicitly execute, inspect evidence,
confirm a finding and export a report. For Mapless: install without Map/account/API
key, create a workspace, review the supplied case, establish credential references
and a finite signed authorization, explicitly execute, inspect evidence and export.
Use the existing guides; a suggestion or discovery run grants no execution authority.

The observer supplies an already qualified synthetic target and reviewed example
case, reachable through the documented container network. Record all setup help;
never substitute real engagement credentials. Human usability evidence is specific
to the mode actually attempted. A result for one mode does not establish a human
result for the other; existing technical acceptance remains separately attributed.

## Record (one row per step)

| Step | Start | End | Completed unaided | Error or confusion (verbatim) | Intervention |
| --- | --- | --- | --- | --- | --- |
| Record mode, candidate and prerequisites (Docker, Git, Python) | | | | | |
| Acquire and configure | | | | | |
| Build and start | | | | | |
| Full CA trust / Mapless not applicable | | | | | |
| Full account/sign-in or Mapless workspace setup | | | | | |
| Full Runner connection or Mapless issuer/credential references | | | | | |
| Engagement/workspace scope and finite execution authorization | | | | | |
| Identities and reviewed case | | | | | |
| Explicit run and evidence | | | | | |
| Full finding/report or Mapless evidence export | | | | | |

## Outputs

Total time from first command to exported report, number of interventions, the
first point the tester could not proceed alone, and every message the tester found
misleading. Each failure becomes a tracked issue; a documentation fix and a product
fix are recorded separately. Raw notes stay out of the repository if they contain
credentials or target details.
