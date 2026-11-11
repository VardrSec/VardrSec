# Kerberos-only database acceptance

The ordinary `db/Dockerfile` builds four Kerberos client packages from exact Debian sources and the narrow ASN.1 backport. A disposable nonroot QEMU TCG guest runs the unchanged Debian package tests, symbol checks and final stripped-library regression. The build boot has no network interface; no host device, privileged mode, added capability or seccomp relaxation is required. PostgreSQL and its package ABI remain unchanged.

The finalizer fails unless each complete package matches the independently reproduced SHA-256 pins in `db/kerberos-vm/qualified-packages.sha256`. It retains original and modified sources, patches, builder scripts, dependency inventory and input-bound receipts in `/usr/share/doc/libkrb5-3/vardr-source/`. Source-only receipts do not invent a Git commit.

Cold builds require room for a 4 GiB guest plus Docker overhead and can take tens of minutes. Full installation builds the database before parallel application builds. Mapless does not build the database.

The image workflow uses the ordinary Compose recipe with only a local image-name override, then checks installed library/copyright bytes, retained source checksums and disposable PostgreSQL CRUD. Inherited Debian-slim omissions are limited to nine explicitly named non-runtime README/changelog/lintian files. No running user installation or persistent database is touched.

Run focused tests:

```sh
python -m unittest discover -s qualification/kerberos-vm
python -m unittest discover -s qualification/kerberos-image
python -m unittest discover -s tests -p 'test_krb5_backport_recipe.py'
python -m unittest discover -s tests -p 'test_database_build_order.py'
```

Historical independently prepared VM runs 43060945526 and 43068431525 produced the four identical pinned packages. This main-based extraction requires its own image and integration acceptance; it does not inherit whole-image clearance from PR104. Package reproducibility is not whole-image reproducibility, a vulnerability waiver, legal compatibility approval or release clearance. Unrelated PR101 changes and component pins are not included.
