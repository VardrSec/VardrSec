# Support and safety limits

This is source-built development software, not a published Community release.
Use the pinned component set and documented commands. A successful build or
completed scan does not certify security, unrestricted platform support or
release readiness.

## Execution

Normal startup is inert. Managed workers require explicit enablement, and each
job still requires valid authorization and local credential grants. Availability
is not execution authority. Legacy manual/advisory workflows and controlled
managed workflows have different documented enforcement boundaries.

Do not rely on controlled execution across host suspend/resume: that behavior is
not qualified. A server-side stop cannot be assumed to reach a disconnected
worker immediately. Preserve uncertain execution records and use the supported
reconciliation procedure; never replay or refund unknown work automatically.
Stop separately enabled workers before stopping their control-plane services.

Host STOP reporting trusts the operator's host. A false exit report from a
compromised trusted host can release accounting prematurely. Reporting credentials
are not execution credentials and must remain outside the worker.

## Platforms and networking

The documented source-built paths cover Windows 11 Docker Desktop with
Linux/amd64 containers and Ubuntu 24.04/amd64 within their stated limits. This
is not operating-system provisioning, universal VPN certification or macOS Docker
support. Split DNS, VPN routes, reconnect behavior and native fallback must be
qualified for the actual environment. Do not add a Docker socket, privileged
container or disabled TLS verification as a workaround.

Standalone controlled Recon is limited to its documented finite DNS-A and
original-host HTTPS/443 GET-root profile. This is not support for every scanner
pipeline. Automatic history import or synchronization between Full and Mapless
is not provided; preserve and export the original installation's records.

## Evidence and distribution

Retain partial results and original journals. Hashes establish correlation and
integrity checks, not independent authenticity or detection accuracy. AI-generated
suggestions cannot approve their own execution or replace human policy review.

Container vulnerability findings and release review remain unresolved. Evaluate
the actual built images before deployment; do not interpret successful evidence
collection as a clean vulnerability scan. Transitive licensing/source delivery,
independent usability and research validation are not established merely by
building the sources or collecting component notices.
