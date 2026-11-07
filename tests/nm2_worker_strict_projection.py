"""Bounded public reader for the installed Strict authority-drift case."""

from pathlib import PurePosixPath, PureWindowsPath
import re

import nm2_worker_acceptance as fixture


def require(condition):
    fixture.require(condition, "strict_authority_drift_receipt_refused")


def _project(raw, selection, before, after, *, desktop):
    platform = "win32" if desktop else "linux"
    require(type(raw) is dict and type(selection) is dict)
    require(len(fixture.canonical(raw)) <= 4 * 1024 * 1024)
    require(raw["schema"] == fixture.STRICT_DRIFT_SCHEMA
            and raw["scenario"] == fixture.STRICT_DRIFT_SCENARIO
            and raw["acceptance_scope"] == fixture.STRICT_DRIFT_SCOPE
            and raw["status"] == fixture.STRICT_DRIFT_PASS
            and raw["stage"] == fixture.STRICT_DRIFT_COMPLETE
            and raw["expected_database_revision"] == "0041persistentruntime"
            and raw["nm2_exit_status"] == "incomplete"
            and raw["platform"] == platform and raw["retained"] is True)
    require(selection["docker_context"] == ("desktop-linux" if desktop else "default"))
    admit = selection["allow_empty_builtin_bridge_id_change"]
    require(type(admit) is bool and (desktop or admit is False))
    for key in ("sources", "images", "project"):
        require(fixture.canonical(raw[key]) == fixture.canonical(selection[key]))
    project = selection["project"]
    require(re.fullmatch(r"vardrsec-nm2-[a-z0-9]{8,24}", project)
            and raw["readiness_volume"] == project + "_worker-ready")
    sources, images = selection["sources"], selection["images"]
    require(type(sources) is dict and set(sources) == fixture.SOURCE_NAMES)
    require(type(images) is dict and set(images) == fixture.IMAGE_NAMES)
    require(all(re.fullmatch(r"sha256:[a-f0-9]{64}", value) for value in images.values()))
    path_type = PureWindowsPath if desktop else PurePosixPath
    for row in sources.values():
        require(type(row) is dict and set(row) == {"path", "commit"}
                and re.fullmatch(r"[a-f0-9]{40}", row["commit"]))
        path = path_type(row["path"])
        require(path.is_absolute() and ".." not in path.parts)

    cases = raw["cases"]
    require(type(cases) is dict and set(cases) == set(fixture.INITIAL_CASES) | {fixture.STRICT_DRIFT_CASE})
    require(fixture.canonical(cases["default_disabled"]) == fixture.canonical({
        "status": "passed", "services": ["api", "db", "proxy", "web"],
        "managed_pending_status": 404, "csrf_write_status": 403, "unauthenticated_read_status": 401,
    }))
    require(all(cases[name] == {"status": "not_run"} for name in fixture.INITIAL_CASES[1:]))
    selected = cases[fixture.STRICT_DRIFT_CASE]
    require(type(selected) is dict and set(selected) == {"status", "proof"} and selected["status"] == "passed")
    measurements = fixture.strict_drift_measurements(selected["proof"])

    kinds = {"containers", "volumes", "networks", "images"}
    for inventory, key in ((before, "before_sha256"), (after, "after_sha256")):
        require(type(inventory) is dict and set(inventory) == kinds
                and all(type(inventory[kind]) is dict for kind in kinds))
        document = fixture.canonical(inventory)
        require(len(document) <= 4 * 1024 * 1024 and fixture.digest(document) == raw[key])
    admitted = fixture.unchanged_inventory(before, after, project, admit_bridge=admit)
    require(len(admitted) <= 1
            and fixture.canonical(admitted) == fixture.canonical(raw["admitted_inventory_diffs"]))
    replacements = {entry["before"]: entry["after"] for entry in admitted}
    for kind in kinds:
        for key, prior in before[kind].items():
            selected_id = replacements.get(key, key) if kind == "networks" else key
            current = after[kind][selected_id]
            if selected_id != key:
                require(prior["driver"] == "bridge" and prior["scope"] == "local"
                        and prior["containers"] == current["containers"] == {})
                current = {**current, "id": key}
            require(fixture.canonical(prior) == fixture.canonical(current))
    stopped = raw["fixture_stop"]
    require(type(stopped) is dict and set(stopped) == {"status", "container_ids", "stop_requested_ids"}
            and stopped["status"] == "stopped_retained")
    owned = set(after["containers"]) - set(before["containers"])
    require(type(stopped["container_ids"]) is list and sorted(owned) == stopped["container_ids"]
            and type(stopped["stop_requested_ids"]) is list
            and set(stopped["stop_requested_ids"]) <= owned
            and len(set(stopped["stop_requested_ids"])) == len(stopped["stop_requested_ids"])
            and len(owned) == len(fixture.STRICT_DRIFT_SERVICES))
    expected = {name: images[name] for name in ("api", "db", "proxy", "web")}
    expected["gate-fixture"] = images["worker"]
    for cid in owned:
        row = after["containers"][cid]
        labels = row["labels"]
        service = labels["com.docker.compose.service"]
        require(re.fullmatch(r"[a-f0-9]{64}", cid) and row["id"] == cid
                and labels["com.docker.compose.project"] == project
                and service in expected and row["image"] == expected.pop(service)
                and all(row["state"][key] is False for key in ("running", "paused", "restarting", "dead")))
    require(not expected)
    return {
        "schema": "vardr.nm2-strict-drift-public/1", "status": fixture.STRICT_DRIFT_PASS,
        "scenario": fixture.STRICT_DRIFT_SCENARIO, "acceptance_scope": fixture.STRICT_DRIFT_SCOPE,
        "platform": platform, "container_platform": "linux", "nm2_exit_status": "incomplete",
        "source_commits": {name: row["commit"] for name, row in sources.items()},
        "stopped_owned_container_count": len(owned), "empty_builtin_bridge_id_change_count": len(admitted),
        "measurements": measurements,
    }


def project(raw, selection, before, after):
    return _project(raw, selection, before, after, desktop=False)


def project_desktop(raw, selection, before, after):
    return _project(raw, selection, before, after, desktop=True)
