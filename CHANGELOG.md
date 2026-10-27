# Changelog

## Unreleased

- Improve first-run prerequisite errors and safe retry of an interrupted initial
  source fetch; preserve existing configuration and changed checkouts. Expose the
  existing generated-password bootstrap mode and display the public CA fingerprint.
  Verify genuinely clean Ubuntu setup, explicit native CA enrollment/removal and
  CLI bootstrap in the installed acceptance job. No automatic trust or routing changes.

- Adopt the owner's Linux-first Community Alpha stabilization priorities and
  refresh proxy OS packages during the development image build. Remaining image
  vulnerability findings still require review; no release is published.

- Add explicit development image SBOM/vulnerability evidence collection and a
  separate strict review command. Blocking findings remain visible; no image
  publication or release readiness is implied by collection success.

- Record the agreed component responsibilities and the first readiness/diagnostics
  implementation reviews. Add a candidate source manifest and validation CI.
- Compose lifecycle, local authentication, component images and the Map status UI
  remain planned; no runnable distribution or release is published by this change.
