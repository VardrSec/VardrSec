# Development image evidence

Collect inventory and vulnerability evidence for all five Compose service images
before considering an image set for release. This is explicit distribution build
tooling; Runner retains installation diagnostics and execution responsibilities.

```sh
python vardrsec.py configure
python vardrsec.py sources
python vardrsec.py build
python image_evidence.py collect
python image_evidence.py check artifacts/image-evidence/run-EXAMPLE/reports
```

Use the actual output directory printed by `collect`. In an already-prepared
workspace, skip `configure`: it refuses an existing `.env`. Source preparation
refuses existing checkouts that differ from the pins. Follow the installation
guide for a clean build workspace; these commands never replace existing state.

## Evidence and interpretation

The pinned Trivy 0.76.1 container generates a CycloneDX SBOM and an unfiltered JSON
vulnerability report for each of `api`, `web`, `db`, `proxy` and `runner`. Reports
include OS and detected language packages, including detected Go binaries. The
receipt records Docker image IDs, selected configuration IDs, platform, repository
digests where present, exported archive hashes, report hashes, scanner digest and
version, database metadata/hash, distribution commit/dirty state, input-file hashes
and declared component pins. Source pins are declarations; they do not prove the
local images were built from those sources. CI builds from the declared pins.

Docker may identify an OCI index while the scanner identifies its selected
configuration. The collector validates the exported index/manifest/configuration
digest chain, platform and ordered layer identities against Docker inspection,
then requires both reports to name that configuration. Classic configuration IDs
are also supported. See the OCI [index](https://github.com/opencontainers/image-spec/blob/main/image-index.md),
[manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md) and
[configuration](https://github.com/opencontainers/image-spec/blob/main/config.md)
specifications. Hashes detect changed evidence; these receipts are unsigned and
are not authenticated provenance, a signature or proof of reproducible builds.

`collect` exits zero when all five image reports are complete and validated,
including when they contain vulnerabilities. The CI workflow is named **Image
evidence collection**: green means collection succeeded. Its logs and receipts
state each image's vulnerability gate. The CI job summary also displays the
verdict and severity counts. This baseline deliberately preserves
findings for remediation rather than introducing an exception list.

`check` reopens the reports, verifies hashes and identities, recomputes counts and
rejects stale databases, unsupported OS/inventory, missing images, incomplete or
malformed evidence. It exits **1** for any HIGH, CRITICAL or UNKNOWN severity or an
end-of-support OS, including findings with no available fix. It exits **2** for
invalid evidence or execution errors; only a valid report set without these
blockers exits zero. Database metadata must be timezone-aware, no more than 48
hours old and no more than five minutes in the future. No stored summary can
override the actual report findings. Counts represent package/path occurrences,
so one advisory may appear several times.

The command does not establish exploitability or absence of vulnerabilities.
Review source advisories and component exposure before remediation. A clear
vulnerability check covers only these frozen images at scan time; functional,
network, certificate, provenance and other release gates remain separate.
See Trivy's [SBOM](https://trivy.dev/docs/latest/guide/supply-chain/sbom/),
[image CLI](https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/)
and [vulnerability coverage](https://trivy.dev/docs/latest/guide/scanner/vulnerability/)
documentation for scanner behavior and limits. Headless/browser provisioning,
undetected non-packaged software and runtime behavior are not certified here.

## Execution and artifact boundary

The collector pulls the exact scanner digest and downloads its database using the
scanner's configured registry sources. The download container mounts only its
disposable cache. Each image scan then runs with networking disabled and the
database frozen. It reads an exported archive through a read-only bind mount;
there is no Docker socket mount and no image or target execution. Version notices,
dependency API lookup and implicit config/ignore files are disabled. No severity
filter or unfixed-vulnerability suppression is used.

Scanner containers have a read-only root filesystem, no capabilities,
no-new-privileges and a temporary writable `/tmp`. Linux uses the invoking UID/GID;
Windows uses UID 0 for Docker Desktop bind-file interoperability. Only disposable
cache and report directories are writable. This does not change the product
containers' users or capabilities. Database access needs outbound registry
connectivity; it does not upload image archives or reports to a scanning service.

The exported archive for each service is deleted after scanning, including on
failure. Reports and the cache remain under ignored `artifacts/image-evidence/`.
CI retains only the reports/logs/receipt for seven days, including partial failure
evidence. Use this workflow for the declared development builds; review metadata
before sharing reports from private images. No platform volumes, credentials or
engagement data are mounted. No images, signatures or releases are published.

## Current release status

The [alpha assessment](alpha-security-assessment.md) records focused remediation,
vendor/exposure questions and the remaining blockers for the newer candidate.
The following paragraph describes the initial baseline before those changes.

The initial local scan blocks all five images. Findings include base OS packages,
embedded Go runtimes and dependencies in Caddy and bundled Runner tools. Repeated
package/path occurrences are not distinct advisories or confirmed exploit paths.
The current official Caddy tag resolved to the already-pinned digest when
inspected. Review vendor affected-status and exposure, prioritize available fixes,
and rescan the replacement image set; no finding is implicitly accepted or
suppressed by this baseline. Successful collection does not close this gate.
Image signing, authenticated build provenance, immutable published release
artifacts and release authorization are also separate work.
