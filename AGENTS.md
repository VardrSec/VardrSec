# VardrSec distribution instructions

- This repository owns Docker Compose installation, startup, stopping, controlled
  updates, compatible component pins and recovery documentation.
- Preserve the separate Map, Runner and Gate source repositories. Do not copy an
  engine or application here, or introduce another diagnostics implementation.
- Runner diagnoses and executes only when explicitly invoked. Map exposes its
  readiness and displays reported status. Gate performs authorization assessment.
- Read the README and architecture decision before implementation. Distinguish
  agreed intent, code in review, released artifacts and verified deployments.
- Use small reviewed changes. Never present missing images, scripts or Compose
  services as runnable; source pins alone do not establish a deployable release.
- Stopping the platform preserves volumes. Updates must account for migrations,
  verified backups and recovery, not merely switching image versions.
- Do not commit credentials, local environment files, private engagement data,
  tool output or machine-specific paths. Do not mount the Docker socket into
  Runner to perform diagnostics.
- Image publication, licensing changes, releases and deployment require explicit
  authorization. Do not choose native/container packaging or authentication by
  implication; record those decisions separately.
