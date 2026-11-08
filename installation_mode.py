"""Explicit installation selection; unmarked installations retain Full behavior."""

import ipaddress
import json
import os
from pathlib import Path
import re
import stat

MARKER = ".installation-mode.json"


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate installation configuration key")
        result[key] = value
    return result


def _read(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or path.is_symlink()
            or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > 16384):
        raise ValueError("Installation configuration must be a small regular file")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object)


def read_mode(root):
    path = Path(root) / MARKER
    if not os.path.lexists(path):
        return "full"
    value = _read(path)
    if (not isinstance(value, dict) or set(value) != {"schema_version", "mode"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["mode"] not in ("full", "mapless")):
        raise ValueError("Invalid installation mode marker")
    return value["mode"]


def write_mode(root, mode):
    if mode not in ("full", "mapless"):
        raise ValueError("Unknown installation mode")
    path = Path(root) / MARKER
    if os.path.lexists(path):
        if read_mode(root) != mode:
            raise ValueError("Installation mode changes require a separate installation and state export")
        return
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump({"schema_version": 1, "mode": mode}, stream)
        stream.write("\n")


def validate_runner_subnet(value):
    """Accept one explicit canonical RFC1918 IPv4 /24, never another route policy."""
    try:
        if not isinstance(value, str):
            raise ValueError
        subnet = ipaddress.ip_network(value, strict=True)
        if (subnet.version != 4 or subnet.prefixlen != 24 or str(subnet) != value
                or not any(subnet.subnet_of(ipaddress.ip_network(block))
                           for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("Runner subnet must be a canonical private IPv4 /24") from None
    return value


def compose_files(root, *, mode=None):
    root = Path(root)
    selected = read_mode(root)
    if mode is not None:
        if mode not in ("full", "mapless"):
            raise ValueError("Unknown installation mode")
        if os.path.lexists(root / MARKER) and selected != mode:
            raise ValueError("Requested mode conflicts with this installation")
        selected = mode
    if selected == "full":
        files = [root / "compose.yaml"]
        overlay = root / ".active-images.json"
    else:
        files = [root / "compose.mapless.json"]
        overlay = root / ".active-images.mapless.json"
        if os.path.lexists(overlay):
            value = _read(overlay)
            if (not isinstance(value, dict) or "services" not in value
                    or set(value) - {"name", "services", "networks"}):
                raise ValueError("Invalid Mapless image selection")
            if "name" in value and (not isinstance(value["name"], str)
                    or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", value["name"])):
                raise ValueError("Invalid Mapless installation project")
            services = value["services"]
            if (not isinstance(services, dict) or set(services) != {"runner"}
                    or not isinstance(services["runner"], dict) or set(services["runner"]) != {"image"}
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(services["runner"]["image"]))):
                raise ValueError("Mapless requires exactly one immutable Runner image")
            if "networks" in value:
                try:
                    subnet = validate_runner_subnet(
                        value["networks"]["runner"]["ipam"]["config"][0]["subnet"]
                    )
                except (ValueError, TypeError, KeyError, IndexError):
                    raise ValueError("Invalid Mapless Runner network selection") from None
                if value["networks"] != {"runner": {"ipam": {"config": [{"subnet": subnet}]}}}:
                    raise ValueError("Invalid Mapless Runner network selection")
    if os.path.lexists(overlay):
        files.append(overlay)
    return files


def read_project(root):
    """Use the installed/restored project even after the caller changes shells."""
    root = Path(root)
    if read_mode(root) != "mapless":
        return None
    path = root / ".active-images.mapless.json"
    if not os.path.lexists(path):
        return None
    compose_files(root)  # Validate the closed image/project selection first.
    return _read(path).get("name")
