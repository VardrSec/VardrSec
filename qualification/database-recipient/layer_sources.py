"""Report PostgreSQL package/source identities across every authenticated OCI layer."""
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from image_evidence import archive_config_id


def require(test, message):
    if not test:
        raise ValueError(message)


def normalize(value):
    name = PurePosixPath(value)
    require(not name.is_absolute() and ".." not in name.parts, "Invalid archive member path")
    return str(name)


def hash_file(stream):
    return hashlib.file_digest(stream, "sha256").hexdigest()


def control(raw):
    result = {}
    field = None
    for line in raw.splitlines():
        if line.startswith(" ") and field:
            result[field] += " " + line.strip()
        elif ":" in line:
            field, value = line.split(":", 1)
            result[field] = value.strip()
        else:
            field = None
    return result


def package(fields):
    name = fields["Package"]
    version = fields["Version"]
    source = re.fullmatch(r"(\S+)(?: \(([^)]+)\))?", fields.get("Source", name))
    require(source, "Invalid source name/version")
    return {"binary": name, "version": version, "source": source[1],
            "source_version": source[2] or version, "built_using": fields.get("Built-Using", ""),
            "static_built_using": fields.get("Static-Built-Using", "")}


def inspect_elf(stream, work):
    if stream.read(4) != b"\x7fELF":
        return None
    probe = work / "elf"
    with probe.open("wb") as out:
        out.write(b"\x7fELF")
        shutil.copyfileobj(stream, out)
    dynamic = subprocess.check_output(["readelf", "--wide", "--dynamic", str(probe)], text=True)
    needed = re.findall(r"\(NEEDED\).*?\[(libdb(?:[-.]\d+)*(?:\.so)(?:\.\d+)*)\]", dynamic)
    info = {}
    if needed:
        with probe.open("rb") as binary:
            info = {"sha256": hash_file(binary), "needed": sorted(set(needed))}
    return info


def inspect_deb(deb, work):
    info = control(subprocess.check_output(["dpkg-deb", "-f", str(deb)], text=True))
    result = {**package(info), "elf_count": 0, "libdb_callers": []}
    with deb.open("rb") as f:
        result["sha256"] = hash_file(f)
    with subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(deb)], stdout=subprocess.PIPE) as contents:
        with tarfile.open(fileobj=contents.stdout, mode="r|*") as payload:
            for member in payload:
                if member.isfile():
                    elf = inspect_elf(payload.extractfile(member), work)
                    if elf is not None:
                        result["elf_count"] += 1
                        if elf:
                            result["libdb_callers"].append({"path": normalize(member.name), **elf})
        while contents.stdout.read(1024 * 1024):
            pass
        require(contents.wait() == 0, "Incomplete binary package")
    return result


def inspect_layer(archive, work, ownership):
    row = {"installed": [], "debs": [], "descriptors": [], "elf_count": 0, "libdb_callers": []}
    for e in archive:
        name = normalize(e.name)
        if not e.isfile():
            continue
        if re.fullmatch(r"var/lib/dpkg/info/[^/]+\.list", name):
            require(e.size <= 16_000_000, "Oversize dpkg file list")
            binary = PurePosixPath(name).name.removesuffix(".list").split(":")[0]
            for path in archive.extractfile(e).read().decode().splitlines():
                ownership[path.lstrip("/")] = binary
        elif name == "var/lib/dpkg/status":
            require(e.size < 8_000_000, "Oversize dpkg status")
            text = archive.extractfile(e).read().decode()
            for stanza in text.split("\n\n"):
                item = control(stanza)
                if item.get("Status") == "install ok installed":
                    row["installed"].append(package(item))
        elif name.endswith((".deb", ".udeb")):
            deb = work / "package.deb"
            with deb.open("wb") as out:
                shutil.copyfileobj(archive.extractfile(e), out)
            row["debs"].append({"path": name, **inspect_deb(deb, work)})
        elif name.endswith(".dsc"):
            require(e.size < 2_000_000, "Oversize source descriptor")
            content = archive.extractfile(e).read()
            data = control(content.decode())
            row["descriptors"].append({"path": name, "sha256": hashlib.sha256(content).hexdigest(),
                                       "source": data.get("Source"), "version": data.get("Version")})
        else:
            elf = inspect_elf(archive.extractfile(e), work)
            if elf is not None:
                row["elf_count"] += 1
                if elf:
                    row["libdb_callers"].append({"path": name, **elf})
    for caller in row["libdb_callers"]:
        caller["owner"] = ownership.get(caller["path"])
    return row


def rootfs(image):
    container = subprocess.check_output(["docker", "create", image, "/bin/true"], text=True).strip()
    require(re.fullmatch("[0-9a-f]{64}", container), "Invalid stopped container ID")
    result = {"direct_copyright": {}, "common_licenses": {}, "shared_doc_links": {},
              "selected_runtime_paths": [], "native_files": {}}
    names = {"newuidmap", "newgidmap", "dpkg-source"}
    suffixes = ("Dpkg/Source/Package/V2.pm", "Dpkg/Source/Package/V3/Quilt.pm")
    native = {"pam_userdb.so", "DB_File.so", "libsasldb.so.2.0.25", "sqv", "gosu"}
    try:
        with subprocess.Popen(["docker", "export", container], stdout=subprocess.PIPE) as export:
            with tarfile.open(fileobj=export.stdout, mode="r|*") as archive:
                for e in archive:
                    path = normalize(e.name)
                    short = PurePosixPath(path).name
                    if short in names or path.endswith(suffixes):
                        result["selected_runtime_paths"].append(path)
                    if e.issym() and path in [f"usr/share/doc/{n}" for n in ("libgcc-s1", "libstdc++6", "libncursesw6")]:
                        result["shared_doc_links"][path] = e.linkname
                    if e.isfile():
                        category = None
                        if re.fullmatch(r"usr/share/doc/[^/]+/copyright", path):
                            category = "direct_copyright"
                        elif path.startswith("usr/share/common-licenses/"):
                            category = "common_licenses"
                        elif short in native or re.fullmatch(r"libgnutls\.so\.30\.\d+\.\d+",short):
                            category = "native_files"
                        if category:
                            result[category][path] = hashlib.sha256(archive.extractfile(e).read()).hexdigest()
            while export.stdout.read(1024 * 1024):
                pass
            require(export.wait() == 0, "Incomplete stopped filesystem")
    finally:
        subprocess.run(["docker", "rm", "-fv", container], check=True)
    return result


def main(image, dest):
    require(re.fullmatch("sha256:[a-f0-9]{64}", image), "Select the accepted immutable Docker image ID")
    details = json.loads(subprocess.check_output(["docker", "image", "inspect", image]))[0]
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        saved = work / "archive.tar"
        subprocess.run(["docker", "image", "save", "--output", str(saved), image], check=True)
        config = archive_config_id(saved, details)
        receipt_path = os.environ.get("VARDRSEC_DATABASE_RECEIPT")
        if receipt_path:
            receipt = json.loads(Path(receipt_path).read_bytes())
            require(image == receipt["image_id"] and config == receipt["origin"]["config_id"],
                    "Image differs from qualified origin")
        layers = []
        ownership = {}
        installed = {}
        with tarfile.open(saved) as src:
            manifests = json.load(src.extractfile("manifest.json"))
            ids = details["RootFS"]["Layers"]
            require(len(manifests) == 1 and len(manifests[0]["Layers"]) == len(ids), "Ambiguous image archive")
            for path, digest in zip(manifests[0]["Layers"], ids):
                stored = src.getmember(normalize(path))
                require(stored.isfile(), "Missing regular layer")
                obj = src.extractfile(stored)
                magic = obj.read(4)
                obj.seek(0)
                if magic == b"\x28\xb5\x2f\xfd":
                    packed = work / "layer.zst"
                    with packed.open("wb") as out:
                        shutil.copyfileobj(obj, out)
                    with (work/"layer.tar").open("wb") as out:
                        subprocess.run(["zstd", "-qdc", str(packed)], check=True, stdout=out)
                else:
                    data = gzip.GzipFile(fileobj=obj) if magic[:2] == b"\x1f\x8b" else obj
                    with (work/"layer.tar").open("wb") as out:
                        shutil.copyfileobj(data, out)
                with (work/"layer.tar").open("rb") as plain:
                    require("sha256:" + hash_file(plain) == digest, "Uncompressed layer digest mismatch")
                    plain.seek(0)
                    with tarfile.open(fileobj=plain, mode="r:") as archive:
                        row = inspect_layer(archive, work, ownership)
                        if row["installed"]:
                            installed = {entry["binary"]: entry for entry in row["installed"]}
                        for caller in row["libdb_callers"]:
                            owner = installed.get(caller["owner"], {})
                            caller.update(source=owner.get("source"), source_version=owner.get("source_version"))
                        layers.append({"diff_id": digest, **row})
        result = {"config_id": config, "image_id": image, "layers": layers, "runtime": rootfs(image),
                  "release_authorized": False, "scope": "Installed dpkg records, all staged debs, direct ELF DT_NEEDED libdb links, selected stopped-runtime evidence"}
        with Path(dest).open("x", encoding="utf-8") as out:
            json.dump(result, out, indent=2)
            out.write("\n")
        print("Authenticated", len(layers), "filesystem layers for", config)


if __name__ == "__main__":
    main(*sys.argv[1:])
