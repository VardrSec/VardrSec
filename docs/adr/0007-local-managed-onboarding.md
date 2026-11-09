# ADR 0007: Connect local setup to existing managed authority

Status: Implementation candidate, not installed acceptance or release approval.

Full already has managed enrollment, finite signed job contracts, persistent
worker lifecycle and host retirement controls. Private acceptance harnesses
should not be required to assemble them for an operator. Distribution supplies
explicit setup commands and delegates each security decision to its existing
component; it adds no engine, network service or authorization protocol.

Preparation discovers and binds the selected local Docker client and frozen
installation. It builds Runner's existing persistent image recipe, creates two
separate external authority volumes and records public trust/configuration.
An offline UID-10001 helper generates each key inside its own private volume.
Only the contract authority is mounted read-only into Map; the operator signing
key never reaches Map, Runner or tools. Worker STOP custody remains unchanged.

Explicit configure applies the managed API override and creates a restricted
Runner API key only after local owner login and explicit acceptance of its
existing plaintext protected-Docker-state storage. Existing unbound connections
are refused; a completed binding is reused, never silently renewed. Durable
partial-setup intent holds uncertain effects for inspection instead of replay.

Job review uses current Map context and the actual worker Gate binary. Separate
terminal confirmation signs the exact context through Runner's existing approval
contract. Registration binds that envelope to the exact review. Local credential
grants remain independent. Explicit worker start delegates the existing
persistent-v3 launch, lock, custody, predecessor and retirement gates. None of
these actions runs as part of normal install or core startup.

Signing volumes remain external authority custody, outside platform snapshots.
Snapshots include the new executable helpers as an optional complete set, keeping
older snapshot formats readable. Restore does not reconstruct authority or enable
managed operation. Explicit configure may reapply the original managed override
after ordinary core recreation; it must not adopt a foreign issuer.

Existing installed evidence retains its original scope. Qualification of this
operator path, the separate matching component pin change and owner acceptance
remain required. This decision does not close NM-2 C09/C10 or accept image risks.
