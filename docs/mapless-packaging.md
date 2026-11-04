# Mapless packaging model (partial NM-3 candidate)

`compose.mapless.json` is a standalone Compose input for one explicit Runner CLI
service. It reuses Full's toolkit build contexts, development image name and
protected state-volume layout. There is no Map/PostgreSQL/proxy service, Full
secret interpolation, injected API credential, public-CA mount or automatic trust change.
The tools profile and help-only command retain explicit invocation; this is not
a managed worker, supervisor or background execution path.

This candidate is not selected by existing lifecycle commands. `compose.yaml`,
`vardrsec.py`, source pins, installed image selection and recovery are unchanged.
Do not merge this input with Full as an override: it is a separate model. The
development image name is intentionally reused, not a newly published image or
an independently verified artifact. No build, pull or startup is part of the
read-only checks below, and this model must not be applied to an existing
installation as an implied transition.

## Safe configuration verification

On a new isolated checkout, without an operator `.env` or target configuration:

```
docker compose -f compose.mapless.json --profile tools config --quiet
```

This validates configuration only; it does not create services, volumes or images.
Unit tests parse JSON using the standard library. Read-only Compose comparison
against Full can use `--no-interpolate` to avoid requiring or rendering real Full
secrets. Never run `config --environment` in shared evidence.

Source/image compatibility, non-root state ownership and actual volume privacy
must still be verified on the final reviewed component cohort. The currently
committed development pins do not include all isolated NM-3 work; this file does
not advance them or claim that a usable Mapless CLI has been shipped. The
standalone controlled Gate currently refuses Linux/Docker; this packaging file
does not route around that refusal or establish fresh Windows Docker acceptance.

## State and transition boundary

The project name and `runner-state:/home/runner/.vardrmap` binding match Full.
Read-only model equality establishes naming compatibility, not an installed
no-loss transition, backup, ACL or authority-restoration guarantee. An explicit
project-name override must remain consistent across any future transition.
Creating a new volume or applying an incompatible image to an old one is not a
migration strategy. Docker administrators can access volumes as documented for
Full; no new privacy promise is introduced.

Mode-aware installation, source preparation, builds, launcher and active-image
selection must be integrated deliberately before this becomes an installer.
Preserve Full by default and refuse unsupported mode/action combinations before
mutation. Existing Full recovery assumes its service and volume set and must not
be called as if it already implements Mapless recovery. Preserve/export local
records and keep an actual non-destructive transition gate; never copy active
authority or silently replay jobs as a shortcut.

This model injects no API credential, but a reused state volume can already
contain Full configuration or credentials. Removing environment entries is not
credential removal, isolation or a trust migration. That persisted-state boundary
must be reviewed explicitly before an installed transition.

Remaining gates include reviewed compatible pins, protected state initialization,
backup/export, fresh Windows11/DockerDesktop installation and actual authorized
recon/Gate/evidence journey with Map inaccessible, Full queue regression, Linux
regression and installed transition without evidence loss. No new recon profile
or discovered-target authorization is chosen here. Docker managed execution
remains disabled/unsupported with its watchdog-hang failure intact.
