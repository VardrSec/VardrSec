"""Seal validated recovery bundles with the standard age tool; no custom cipher."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

import recovery

ALLOWED = (
    set(recovery.FILES)
    | {"snapshot.json", "database.dump", "images.tar.gz"}
    | {f"{v}.tar.gz" for v in recovery.VOLUMES}
)


def age():
    executable = shutil.which("age")
    if executable is None:
        raise ValueError("Install the official age v1.3.2 tool and place it on PATH")
    result = subprocess.run(
        [executable, "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.stdout.strip().lstrip("v") != "1.3.2":
        raise ValueError("This packaging slice is tested with age v1.3.2")
    return executable


def check_recipient(recipient):
    if not re.fullmatch(r"age1[ac-hj-np-z02-9]{58}", recipient):
        raise ValueError("Use a native X25519 age recipient from age-keygen")
    return age()


def encrypted_backup(root, destination, recipient):
    destination = destination.resolve()
    check_recipient(recipient)
    if destination.exists():
        raise ValueError("Encrypted backup destination must not exist")
    with tempfile.TemporaryDirectory(
        prefix=".vardrsec-backup-", dir=destination.parent
    ) as temporary:
        staging = Path(temporary)
        staging.chmod(0o700)
        recovery.backup(root, staging / "bundle")
        seal(staging / "bundle", destination, recipient, announce=False)
    print(
        "Encrypted backup completed; private plaintext staging removed. Applications remain stopped."
    )


def seal(source, destination, recipient, *, announce=True):
    source, destination = source.resolve(), destination.resolve()
    executable = check_recipient(recipient)
    metadata = recovery.validate(source)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output, tempfile.TemporaryFile() as errors:
            with subprocess.Popen(
                [executable, "--encrypt", "--recipient", recipient],
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=errors,
            ) as process:
                try:
                    with tarfile.open(fileobj=process.stdin, mode="w|") as archive:
                        for name in sorted(set(metadata["files"]) | {"snapshot.json"}):
                            path = source / name
                            info = archive.gettarinfo(str(path), arcname=name)
                            info.uid = info.gid = 0
                            info.uname = info.gname = ""
                            with path.open("rb") as data:
                                archive.addfile(info, data)
                    process.stdin.close()
                    if process.wait() != 0:
                        raise ValueError("age encryption failed")
                except BaseException:
                    process.kill()
                    raise
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    if announce:
        print(
            "Encrypted package completed. The source recovery bundle is retained and remains private plaintext."
        )


def unseal(source, destination, identity):
    source, destination, identity = (
        source.resolve(),
        destination.resolve(),
        identity.resolve(),
    )
    if destination.exists():
        raise ValueError("Unseal destination must not exist")
    # Native identities avoid plugin execution or an unexpected interactive prompt.
    if identity.stat().st_size > 8192:
        raise ValueError("Use a native age identity file")
    keys = [
        line.strip()
        for line in identity.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not keys or any(
        not re.fullmatch(r"AGE-SECRET-KEY-1[AC-HJ-NP-Z02-9]{58}", key) for key in keys
    ):
        raise ValueError("Use a protected native X25519 age identity file")
    executable = age()
    # Plaintext exists only in a private staging directory until authentication,
    # strict member validation and recovery checksums have all succeeded.
    with (
        tempfile.TemporaryDirectory(
            prefix=".vardrsec-unseal-", dir=destination.parent
        ) as temporary,
        tempfile.TemporaryFile() as errors,
    ):
        staging = Path(temporary)
        staging.chmod(0o700)
        with subprocess.Popen(
            [executable, "--decrypt", "--identity", str(identity), str(source)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=errors,
        ) as process:
            try:
                seen = set()
                with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                    for member in archive:
                        if (
                            member.name not in ALLOWED
                            or not member.isfile()
                            or member.name in seen
                        ):
                            raise ValueError(
                                "Encrypted package contains an unsupported or duplicate entry"
                            )
                        seen.add(member.name)
                        descriptor = os.open(
                            staging / member.name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                        )
                        with (
                            os.fdopen(descriptor, "wb") as output,
                            archive.extractfile(member) as data,
                        ):
                            shutil.copyfileobj(data, output)
                # tar permits trailing padding; drain it so age authenticates EOF.
                shutil.copyfileobj(process.stdout, _Discard())
                if process.wait() != 0:
                    raise ValueError(
                        "Wrong identity, corrupted or incomplete encrypted package"
                    )
            except BaseException:
                process.kill()
                raise ValueError(
                    "Encrypted package authentication or validation failed"
                ) from None
        metadata = recovery.validate(staging)
        if seen != set(metadata["files"]) | {"snapshot.json"}:
            raise ValueError("Encrypted package does not match its snapshot manifest")
        # mkdir is exclusive; publish only after complete authentication. A failed
        # final copy leaves a private incomplete directory, never a Docker restore.
        destination.mkdir(mode=0o700)
        for name in seen:
            with (staging / name).open("rb") as data:
                descriptor = os.open(
                    destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                with os.fdopen(descriptor, "wb") as output:
                    shutil.copyfileobj(data, output)
    print(
        "Authenticated recovery bundle published. Use the existing verified restore command."
    )


class _Discard:
    def write(self, data):
        return len(data)
