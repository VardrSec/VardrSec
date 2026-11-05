# NM-3 direct encrypted-backup CLI verification

This isolated CI branch extends verified encrypted recovery commit
`43fb9f71ad111567f65b4132a66d4373284dc6b3` and run 41969912561.
It installs unchanged reviewed source
`07307a2707eefd772f00eeac6d4977680f854c4d` with the same component pins.

Unlike the earlier seal-existing-backup test, this lane invokes the documented
`python vardrsec.py backup --destination ... --recipient ...` command against
the fresh synthetic installation. It requires successful ciphertext publication,
removal of the command's private temporary plaintext staging, and release of
its installation lock. It then checks wrong-key, truncated and tampered package
refusal, authenticates the original package, validates snapshot schema v4, binds
bundled Python code to reviewed source, and restores through the bundle's CLI.
Database/volume fingerprints and restored-install refusal remain required.

The official age 1.3.2 build, Go 1.27.3 compiler, checksum and origin commit pins,
fresh hosted VM/empty local daemon guards, and exact public receipt upload path
are unchanged. Keys, configuration, plaintext, ciphertext and raw logs remain
private in the disposable VM. No explicit fixture data deletion is added; the
existing encrypted-backup command removes its own temporary plaintext staging.

Only `codex/nm3-direct-encrypted-verification` triggers this new workflow.
The installer and source changelog remain byte-identical to the reviewed candidate.
This test does not establish final NM-3 cohort, Mapless, Windows, upgrade/no-loss
or SQLite snapshot non-mutation acceptance. Hosted results are unproven until
the exact committed workflow completes.
