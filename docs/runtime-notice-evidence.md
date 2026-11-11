# Runtime notice and native identity evidence

`runtime_notice_evidence.py` consumes a tar stream from a **stopped, never-started**
container created from the exact candidate image. CI controls container creation,
export and cleanup; the collector does not call Docker, start services or load any
native code. Use freshly built images, not exports of running application/user
containers.

```sh
# CI supplies container_id from docker create of the exact image_id, never starts it.
# image_id is docker image inspect --format '{{.Id}}' of that same image.
set -o pipefail
docker export "$container_id" | python runtime_notice_evidence.py \
  --image-id "$image_id" --service api \
  --distribution-commit "$distribution_commit" \
  --output artifacts/api-runtime-notices.tar
```

Output is an exclusively created tar containing `manifest.json` and retained
legal texts under `notices/`. No raw export is retained. Bind its tar SHA-256,
manifest `image_id` and `distribution_commit` to the corresponding image-evidence
receipt. The collector validates identifier syntax, **not** Docker provenance:
CI must ensure the exported container's inspected image ID matches the receipt.
Do not reuse evidence across rebuilt images even if the image tag is unchanged.

## Exact retention boundary

Only conventional basenames LICENSE/LICENCE, COPYING, NOTICE and copyright
(case-insensitive, including normal suffixes) are retained beneath:

- `/usr/share/doc/`, `/usr/share/licenses/`
- `/usr/local/lib/python3.<minor>/site-packages/`
- `/usr/local/lib/node_modules/`, `/app/node_modules/`, `/app/.next/`
- `/opt/vardrtools/provenance/`
- Exact top-level `/app/LICENSE`, `/app/NOTICE`, `/app/COPYING`

The exact generated names `GO-LICENSE`, `openpgp-LICENSE` and
`dependency-notices.tar.gz` are additionally allowed under `/usr/share/licenses/`
and `/opt/vardrtools/provenance/`. Compressed notice archives stay opaque.

No package metadata, application configuration, home directory, environment file,
full filesystem export or executable is retained. Arbitrary legal text in a README,
source comments, compressed copyright files and nonconventional paths are not
claimed covered. Link/special-file entries in scope are explicitly unresolved:
links are not dereferenced and their targets are not recorded. This is not a
complete license classifier or an extraction of all legally required material.

Native **hashes and paths only** are collected for:

- `/usr/local/lib/python3.<minor>/site-packages/psycopg_binary.libs/*.so*`
- `/app/node_modules/@img/sharp-libvips-linux-x64/lib/libvips-cpp.so.*`

Compare these file hashes with the verified upstream package inventories, not
just filenames/versions. This can close the selected native-byte identity subset;
it does not prove whole-wheel identity, native build provenance or completeness
of corresponding source. API/web expected native files and expected notices must
be checked by the reviewer; zero discoveries are reported, never called success
or compliance. Other architectures and paths require explicit scoped additions.

## Bounds and checks

The collector uses streaming tar reads without filesystem extraction. It refuses
absolute/traversal/backslash paths, duplicate selected paths, malformed context,
truncated selected content, more than 10,000 selected entries, legal texts over
4 MiB each or 64 MiB total, and native files over 256 MiB each. It hashes selected
native data in chunks without retaining it. Output tar metadata/order is fixed,
so identical selected input bytes and context produce identical artifacts.

The schema is `vardr.runtime-notice-evidence/1`:
`notices` contains path, artifact_path, SHA-256, size, false content_reviewed and
representation (unreviewed_file_bytes or opaque_archive). Selected compressed
files/archives are retained verbatim, never decompressed or claimed inspected;
`native_files` contains path, SHA-256 and size;
`unresolved_selected_entries` contains selected path and reason.
`release_clearance` and `coverage_complete` are always false. Neither a zero exit
status nor the presence of a license filename is legal approval.

Tests use synthetic tar inputs only. Actual candidate-image extraction belongs in
CI and remains unverified until that run and its artifact/receipt checks succeed.

## Separate source-delivery artifact

The workflow also copies only reviewed image source/provenance directories:
`/usr/share/doc/libxml2/vardr-source`, `/usr/share/licenses/gosu/source`, and
`/opt/vardrtools/provenance`. It checks the libxml2 and gosu retained SHA256SUMS
and retains Runner's per-tool source manifests and patch/source archives for
independent review. This separate artifact includes source/package metadata,
unlike the narrow notice collector. It is not a whole-filesystem export or
proof that all transitive corresponding source is complete.

The native hash allowlist also covers versioned `libxml2` and `libpcap` shared
library payloads under `/usr/lib` (including multiarch directories). These are
hash-only entries for comparison to source-build/regression receipts; links
remain explicitly unresolved and are never followed by the collector.
