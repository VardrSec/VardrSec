#!/usr/bin/env python3
"""Filter a stopped-container Docker export into bounded notice/hash evidence.

Reads a tar stream; never starts containers or extracts filesystem paths. Only
allowlisted conventional legal texts are retained. Selected native binaries are
hashed, not retained. No legal clearance or source completeness is implied.
"""
import argparse
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import sys
import tarfile

MAX_NOTICE = 4 * 1024 * 1024
MAX_NOTICES_TOTAL = 64 * 1024 * 1024
MAX_NATIVE = 256 * 1024 * 1024
MAX_SELECTED = 10000
NOTICE_ROOTS = ('usr/share/doc/', 'usr/share/licenses/',
                'usr/local/lib/node_modules/', 'app/node_modules/', 'app/.next/')
LEGAL_NAME = re.compile(r'(?:licen[cs]e|copying|notice|copyright)(?:[._-][a-z0-9._-]+)?', re.I)
PYTHON_SITE = re.compile(r'^usr/local/lib/python3\.[0-9]+/site-packages/')
NATIVE = re.compile(
    r'^(?:usr/local/lib/python3\.[0-9]+/site-packages/psycopg_binary\.libs/[^/]+\.so(?:\.[^/]+)*'
    r'|app/node_modules/@img/sharp-libvips-linux-x64/lib/libvips-cpp\.so(?:\.[^/]+)*)$')


def path_name(raw):
    name = raw[2:] if raw.startswith('./') else raw
    p = PurePosixPath(name)
    if not name or p.is_absolute() or '..' in p.parts or '\\' in name:
        raise ValueError('unsafe export path')
    return str(p)


def selection(name):
    if NATIVE.fullmatch(name):
        return 'native'
    if LEGAL_NAME.fullmatch(PurePosixPath(name).name) and (
            name.startswith(NOTICE_ROOTS) or PYTHON_SITE.match(name)
            or name in {'app/LICENSE', 'app/NOTICE', 'app/COPYING'}):
        return 'notice'
    return None


def validate_context(image_id, service, revision):
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
        raise ValueError('full Docker image configuration ID required')
    if service not in {'api', 'web', 'runner', 'proxy', 'db'}:
        raise ValueError('unknown service')
    if not re.fullmatch(r'[a-f0-9]{40}', revision):
        raise ValueError('full distribution commit required')


def collect(stream, image_id, service, revision):
    validate_context(image_id, service, revision)
    manifest = {'schema': 'vardr.runtime-notice-evidence/1', 'image_id': image_id,
                'service': service, 'distribution_commit': revision,
                'release_clearance': False, 'image_identity_source': 'caller-supplied Docker inspect ID; bind to image receipt',
                'scope': 'allowlisted conventional legal filenames and selected native hashes only',
                'notices': [], 'native_files': [], 'unresolved_selected_entries': []}
    files, seen, notice_total = {}, set(), 0
    with tarfile.open(fileobj=stream, mode='r|*') as archive:
        for member in archive:
            name = path_name(member.name)
            kind = selection(name)
            if not kind or member.isdir():
                continue
            if name in seen:
                raise ValueError('duplicate selected export path')
            seen.add(name)
            if len(seen) > MAX_SELECTED:
                raise ValueError('selected entry count exceeds limit')
            if not member.isfile():
                # Do not dereference links, record targets, or copy special files.
                manifest['unresolved_selected_entries'].append({'path': name, 'reason': 'not a regular file'})
                continue
            limit = MAX_NOTICE if kind == 'notice' else MAX_NATIVE
            if member.size < 0 or member.size > limit:
                raise ValueError('selected entry size exceeds limit')
            if kind == 'notice':
                notice_total += member.size
                if notice_total > MAX_NOTICES_TOTAL:
                    raise ValueError('total legal text size exceeds limit')
            digest, chunks, length = hashlib.sha256(), [], 0
            reader = archive.extractfile(member)
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                length += len(chunk)
                digest.update(chunk)
                if kind == 'notice':
                    chunks.append(chunk)
            if length != member.size:
                raise ValueError('truncated selected export member')
            row = {'path': name, 'sha256': digest.hexdigest(), 'size': length}
            if kind == 'notice':
                destination = 'notices/' + name
                files[destination] = b''.join(chunks)
                row['artifact_path'] = destination
                row['content_reviewed'] = False
                row['representation'] = ('opaque_archive' if name.lower().endswith(
                    ('.gz', '.bz2', '.xz', '.zip', '.tar', '.tgz', '.zst')) else 'unreviewed_file_bytes')
                manifest['notices'].append(row)
            else:
                manifest['native_files'].append(row)
    for key in ('notices', 'native_files', 'unresolved_selected_entries'):
        manifest[key].sort(key=lambda row: row['path'])
    manifest['notice_count'] = len(manifest['notices'])
    manifest['native_file_count'] = len(manifest['native_files'])
    manifest['coverage_complete'] = False
    files['manifest.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    return manifest, files


def write_bundle(files, destination):
    with open(destination, 'xb') as output:
        with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name, data in sorted(files.items()):
                member = tarfile.TarInfo(name)
                member.mode, member.size, member.mtime = 0o644, len(data), 0
                archive.addfile(member, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--service', required=True)
    parser.add_argument('--distribution-commit', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    manifest, files = collect(sys.stdin.buffer, args.image_id, args.service, args.distribution_commit)
    write_bundle(files, args.output)
    print(json.dumps({'service': args.service, 'notices': manifest['notice_count'],
                      'native_files': manifest['native_file_count'],
                      'unresolved_selected_entries': len(manifest['unresolved_selected_entries']),
                      'release_clearance': False}))


if __name__ == '__main__':
    main()
