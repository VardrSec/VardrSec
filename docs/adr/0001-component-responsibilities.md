# ADR 0001: Keep lifecycle, diagnostics, presentation and assessment separate

Status: Accepted, 2026-10-25. Implementation is staged and not yet released.

## Decision

VardrSec installs, starts, stops and updates the platform through Docker Compose.
It owns distribution compatibility and recovery procedures, while application
source remains in the existing component repositories.

VardrRunner diagnoses installation, connectivity, tools and configuration. Extend
its existing doctor/status commands and keep local execution, credentials, jobs
and result transport there. Diagnosis must not silently repair or execute scans.

VardrMap provides the web interface and engagement workflow. Its backend owns
database/schema readiness and exposes it through an interface Runner can consume.
Map will display reported component and runner status with observation times,
including stale, unknown and unreachable states.

VardrGate remains the specialized authorization-testing engine and standalone CLI.
Do not put platform lifecycle or installation diagnostics in the engine.

## Consequences

No monorepo conversion, duplicate doctor, permanent Gate daemon or implicit scan
worker is required. Platform startup and scan execution remain separate operator
actions. Stop/start preserves user data. Updates need a tested migration and
recovery path; image rollback alone does not establish database compatibility.

The initial `versions.json` uses JSON for dependency-free manifest validation.
It pins candidate sources and explicitly says the distribution is not runnable;
there are no published image references or release claims. Future release tooling
must validate artifact provenance and enforce complete, compatible image pins.

Local authentication is merged in Map #111/#112. Container Runner packaging is
accepted in [ADR 0002](0002-runner-container.md), with native support retained.
Network/certificate configuration, image publication and licensing remain separate decisions. Existing
hosted behavior and component authorization controls must be preserved.
