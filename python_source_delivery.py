#!/usr/bin/env python3
"""Collect registry-hash-verified sdists for the exact Python SBOM inventory.

No package is installed or executed. This is source delivery evidence, not license
clearance or proof that an sdist rebuilds a particular wheel/native dependency.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from urllib.parse import quote, unquote, urlsplit
from urllib.request import urlopen
import zipfile

MAX_BYTES = 128 * 1024 * 1024


def fetch(url):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in {'pypi.org', 'files.pythonhosted.org'}:
        raise ValueError('source must be on the official HTTPS Python registry')
    with urlopen(url, timeout=90) as response:
        final = urlsplit(response.url)
        if final.scheme != 'https' or final.hostname not in {'pypi.org', 'files.pythonhosted.org'}:
            raise ValueError('unexpected registry redirect')
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('registry file exceeds limit')
    return data


def normalize(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def inventory(sbom):
    packages = set()
    for item in sbom.get('components', []):
        purl = item.get('purl', '')
        if not purl.startswith('pkg:pypi/'):
            continue
        path = purl[len('pkg:pypi/'):].split('?', 1)[0].split('#', 1)[0]
        name, separator, version = path.rpartition('@')
        name, version = normalize(unquote(name)), unquote(version)
        if not separator or not re.fullmatch(r'[a-z0-9][a-z0-9.-]*', name) or not re.fullmatch(r'[a-zA-Z0-9.!+_-]+', version):
            raise ValueError('invalid Python package identity')
        if str(item.get('version', '')) != version:
            raise ValueError('SBOM version mismatch')
        packages.add((name, version))
    if not packages:
        raise ValueError('no Python package inventory')
    return sorted(packages)


def legal_files(data, filename):
    """Retain legal texts without extracting archive paths or following links."""
    result = {}
    total = 0
    def add(name, size, read):
        nonlocal total
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or '\\' in name:
            raise ValueError('unsafe source archive path')
        if not re.search(r'(^|[/_.-])(licen[cs]e|copying|copyright|notice|authors)([/_.-]|$)', name, re.I):
            return
        total += size
        if size > 8 * 1024 * 1024 or total > 32 * 1024 * 1024:
            raise ValueError('legal text size limit exceeded')
        if name in result:
            raise ValueError('duplicate legal text path')
        result[name] = read()
    if filename.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for entry in archive.infolist():
                if not entry.is_dir() and (entry.external_attr >> 16) & 0o170000 != 0o120000:
                    add(entry.filename, entry.file_size, lambda e=entry: archive.read(e))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
            for entry in archive:
                if entry.isfile():
                    add(entry.name, entry.size, lambda e=entry: archive.extractfile(e).read())
    return result


def collect(sbom_bytes, retrieve=fetch):
    manifest = {'schema': 'vardr.python-source-delivery/1',
                'sbom_sha256': hashlib.sha256(sbom_bytes).hexdigest(),
                'release_clearance': False,
                'scope': 'PyPI sdists only; wheel equivalence and bundled native sources unverified',
                'packages': []}
    files = {'input.cdx.json': sbom_bytes}
    for name, version in inventory(json.loads(sbom_bytes)):
        row = {'name': name, 'version': version, 'status': 'missing_sdist'}
        manifest['packages'].append(row)
        try:
            metadata_url = f'https://pypi.org/pypi/{quote(name)}/{quote(version)}/json'
            metadata_bytes = retrieve(metadata_url)
            metadata = json.loads(metadata_bytes)
            info = metadata['info']
            if normalize(info['name']) != name or str(info['version']) != version:
                raise ValueError('registry identity mismatch')
            prefix = f'{name}/{version}'
            files[f'{prefix}/registry.json'] = metadata_bytes
            row['metadata_url'] = metadata_url
            row['metadata_sha256'] = hashlib.sha256(metadata_bytes).hexdigest()
            candidates = [x for x in metadata['urls'] if x['packagetype'] == 'sdist']
            if len(candidates) != 1:
                row['reason'] = 'expected one sdist, found ' + str(len(candidates))
                continue
            artifact = candidates[0]
            filename = artifact['filename']
            if Path(filename).name != filename or '\\' in filename or filename in {'.', '..'}:
                raise ValueError('unsafe registry filename')
            expected = artifact['digests']['sha256']
            if not re.fullmatch(r'[a-f0-9]{64}', expected):
                raise ValueError('invalid registry digest')
            data = retrieve(artifact['url'])
            digest = hashlib.sha256(data).hexdigest()
            if digest != expected:
                raise ValueError('sdist SHA256 mismatch')
            notices = legal_files(data, filename)
            path = f'{prefix}/source/{filename}'
            files[path] = data
            row.update(status='source_retained', source_url=artifact['url'], source_path=path,
                       sha256=digest, size=len(data), yanked=bool(artifact.get('yanked')), notices=[])
            for member, content in sorted(notices.items()):
                destination = f'{prefix}/notices/{member}'
                files[destination] = content
                row['notices'].append({'path': destination, 'source_member': member,
                                       'sha256': hashlib.sha256(content).hexdigest()})
            if not notices:
                row['notice_review'] = 'no_conventional_legal_filename_found'
        except Exception as error:
            row.update(status='collection_failed', reason=f'{type(error).__name__}: {error}')
    manifest['complete_sdist_coverage'] = all(p['status'] == 'source_retained' for p in manifest['packages'])
    files['manifest.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    return manifest, files


def write_bundle(files, destination):
    """Stable uncompressed tar for identical captured inputs; never overwrite."""
    with open(destination, 'xb') as stream:
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name, data in sorted(files.items()):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = 0o644
                entry.mtime = 0
                archive.addfile(entry, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sbom', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists')
    manifest, files = collect(args.sbom.read_bytes())
    write_bundle(files, args.output)
    print(json.dumps({'output': str(args.output), 'packages': len(manifest['packages']),
                      'complete_sdist_coverage': manifest['complete_sdist_coverage'],
                      'sha256': hashlib.sha256(args.output.read_bytes()).hexdigest()}))
    return 0 if manifest['complete_sdist_coverage'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
