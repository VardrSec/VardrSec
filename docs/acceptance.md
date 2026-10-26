# Distribution acceptance plan

The first source-level slice is reviewed in Map #110 and Runner #82. Local
verification passed 1,103 Map backend tests (one skip), six PostgreSQL migration
checks, and 1,570 Runner tests (ten opt-in skips) at 96.48% Runner coverage.

The real three-product loopback harness passed 143 checks on each setup:

| Fixture | Map readiness | Requested Runner platform check |
|---|---|---|
| PostgreSQL 18 with real migrations | Ready | Healthy, exit 0 |
| SQLite create-all without Alembic marker | Not ready | Migration readiness fails, exit 1 |

The negative SQLite result is expected and tested; it must not be hidden by
stamping the schema. Diagnostics sent no target requests, skipped release discovery
when requested, and did not print the API key. These are source-snapshot checks,
not a distribution installation or hosted deployment verification.

Before a runnable alpha, require:

- One distribution download installs the pinned components without three source
  checkouts and starts the local UI/API/database with explicit secret setup.
- Local login works without required VardrSec hosting or an external provider;
  existing hosted login and tenant/authorization controls remain supported.
- Trusted HTTPS works on a fresh supported machine and clean browser profile,
  with an explicit documented trust-enrollment step if a local CA is used. The
  normal installation URL must show no certificate warning; browser/API/Runner
  certificate checks remain enabled. Never advertise Compose startup alone as
  completing trust enrollment or use insecure flags to pass this acceptance.
- Verify certificate persistence/renewal, restart and upgrade, CA-key protection,
  recovery and trust removal. A reverse proxy must accept forwarded scheme/IP
  metadata only from its configured trusted peers; backend/database ports remain
  private or loopback-bound. Missing trust and incomplete backend upgrades must
  produce actionable Runner/login diagnostics.
- Runner diagnoses actual required components and tools; Map shows status with
  observation times and handles stale/unreachable/unknown state honestly.
- Startup and diagnostics execute no scans. The operator reviews a case and
  explicitly invokes Runner; Gate's result/evidence reaches Map without automatic
  promotion into a confirmed finding.
- Stop/start preserves engagement data, Runner state and evidence. Backup restores
  into a fresh installation with evidence hashes and access intact.
- An upgrade and a failed upgrade have tested migration/recovery behavior.
- Test supported Linux/macOS/Windows environments, resource use, host-local/VPN
  target reachability and declared outbound traffic. Measure time to the first
  correct reviewed authorization test and assistance required.

Map's self-signed HTTPS browser fixture tests authentication and session behavior;
it does not establish trusted first-install acceptance. The distribution remains
unreleased until the above trust checks pass without certificate-error overrides.
Local authentication is defined in Map [#111](https://github.com/VardrSec/VardrMap/pull/111)
and its browser integration in [#112](https://github.com/VardrSec/VardrMap/pull/112).
