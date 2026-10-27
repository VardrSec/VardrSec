# Encrypted recovery packages

Use official [age v1.3.2](https://github.com/FiloSottile/age/releases/tag/v1.3.2)
on PATH for encryption commands. This slice uses native X25519 recipient/identity
files and age's existing authenticated streaming format. It implements no cipher,
key derivation or proprietary encrypted format. Normal installation, diagnostics
and plaintext restore commands still work without age.

Generate a recovery identity on a protected recovery machine:

```sh
age-keygen --output /private/offline-recovery-identity.txt
age-keygen -y /private/offline-recovery-identity.txt
```

Keep the private identity separately from backups and the installation. Use a
protected encrypted drive and private ACLs/permissions; identity loss prevents
recovery. The public `age1...` recipient may be supplied to the backup machine.
Never paste private keys into command arguments, environment variables or Git.
Official binaries are available for Windows/macOS/Linux; development CI builds
the pinned official Go module with its checksum verification.

Create an encrypted backup directly:

```sh
python vardrsec.py backup --destination /private/backups/before-update.age \
  --recipient age1YOUR_PUBLIC_RECIPIENT
```

Replace the recipient placeholder. The command checks age/recipient/destination
before maintenance, quiesces the platform, uses private plaintext staging, seals
the complete portable bundle, then removes staging. Applications remain stopped
as with ordinary backup. Allow space for both staging and encrypted output.
An existing output is never overwritten. An interrupted encrypted file is not a
completed backup and fails authentication during recovery.

To encrypt an existing completed working bundle:

```sh
python vardrsec.py seal-backup --backup /private/working-backup \
  --destination /private/backups/before-update.age --recipient age1YOUR_PUBLIC_RECIPIENT
```

This retains the original plaintext bundle. The controlled updater still needs a
private working backup for rehearsal and cancellation; export it encrypted for
retention/transfer, and manage its plaintext lifetime explicitly. Encryption does
not retroactively remove copies, snapshots or synchronized versions of plaintext.

Authenticate and recover the portable bundle into a new private directory:

```sh
python vardrsec.py unseal-backup --backup /private/backups/before-update.age \
  --identity /private/offline-recovery-identity.txt --destination /private/unsealed
python vardrsec.py restore --backup /private/unsealed \
  --destination /private/restored-platform --project vardrsec-restore-drill
```

Unsealing stages plaintext privately. Wrong identity, tampering, truncation,
unsupported/duplicate archive entries or recovery checksum failure publish no
destination and invoke no Docker restore. Only a completely authenticated and
validated bundle is published. The resulting directory is plaintext and requires
the same protection and credential review as any [recovery bundle](recovery.md).

Age protects confidentiality and integrity; it does not identify the creator of
a package. Accept trusted backups, retain recovery identities independently, and
prove decryption plus restoration before relying on an encrypted backup. No
plaintext or private-key artifact is uploaded by CI. Fresh OS trust acceptance is
a separate test from backup encryption.
