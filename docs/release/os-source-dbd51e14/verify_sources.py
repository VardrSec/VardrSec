#!/usr/bin/env python3
"""Acquire/check pinned bytes without extracting or executing source packages."""
import argparse, bz2, gzip, hashlib, io, json, lzma, pathlib, re, subprocess, tarfile, tempfile, urllib.request, zlib


def digest(data, algorithm='sha256'):
    return hashlib.new(algorithm, data).hexdigest()


def fields(text):
    result = {}; key = None
    for line in text.splitlines():
        if line.startswith(' ') and key:
            result[key] += '\n' + line[1:]
        elif ':' in line:
            key, value = line.split(':', 1); result[key] = value.strip()
    return result


def verify(root, lock, provenance, keyring):
    for row in lock['files']:
        data = (root / row['file']).read_bytes()
        if len(data) != row['bytes'] or digest(data) != row['sha256']:
            raise ValueError('Pinned bytes differ: ' + row['file'])
        if row.get('sha512') and digest(data, 'sha512') != row['sha512']:
            raise ValueError('SHA512 mismatch: ' + row['file'])
        if row.get('sha512'):
            recipe = (root / 'alpine-recipes' / row['source'] / 'APKBUILD').read_text()
            checks = {name: value for value, name in re.findall(r'^([0-9a-f]{128})\s+(\S+)$', recipe, re.M)}
            if checks.get(pathlib.Path(row['file']).name) != row['sha512']:
                raise ValueError('Source checksum not in pinned APKBUILD')
        if row.get('git_blob') and digest(b'blob ' + str(len(data)).encode() + b'\0' + data, 'sha1') != row['git_blob']:
            raise ValueError('Git blob mismatch: ' + row['file'])
    if not provenance:
        return
    if not keyring:
        raise ValueError('--debian-keyring is required for signature verification')
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        indexes = {}
        for chain in lock['debian_chains']:
            verified = tmp / (chain['name'] + '.Release')
            key = root / 'pgdg-key.asc' if chain['keyring'] == 'pgdg' else pathlib.Path(keyring)
            subprocess.run(['sqv', '--keyring', str(key), '--cleartext', str(root / chain['inrelease']), '--output', str(verified)], check=True)
            release = fields(verified.read_text())
            expected = {p: (h, int(n)) for h, n, p in (line.split() for line in release['SHA256'].splitlines() if line.strip())}
            raw = (root / chain['index']).read_bytes()
            if expected[chain['index_release_path']] != (digest(raw), len(raw)):
                raise ValueError('Index differs from authenticated Release')
            text = (bz2.decompress(raw) if chain['index'].endswith('.bz2') else lzma.decompress(raw)).decode()
            indexes[chain['index']] = {(r['Package'], r['Version']): r for r in map(fields, text.split('\n\n')) if 'Package' in r}
        for row in lock['files']:
            if row['kind'] != 'debian-source':
                continue
            record = indexes[row['index']][row['source'], row['version']]
            checks = {n: (h, int(s)) for h, s, n in (line.split() for line in record['Checksums-Sha256'].splitlines() if line.strip())}
            if checks[pathlib.Path(row['file']).name] != (row['sha256'], row['bytes']):
                raise ValueError('Source differs from authenticated index')
        raw = (root / 'alpine-APKINDEX.tar.gz').read_bytes()
        inflater = zlib.decompressobj(31); signature_tar = inflater.decompress(raw); signed = inflater.unused_data
        with tarfile.open(fileobj=io.BytesIO(signature_tar)) as archive:
            signatures = [m for m in archive if m.name.startswith('.SIGN.RSA.')]
            if len(signatures) != 1:
                raise ValueError('Unexpected Alpine signature count')
            (tmp / 'signature').write_bytes(archive.extractfile(signatures[0]).read())
        (tmp / 'signed').write_bytes(signed)
        subprocess.run(['openssl', 'dgst', '-sha1', '-verify', str(root / 'alpine-index-key.pem'), '-signature', str(tmp / 'signature'), str(tmp / 'signed')], check=True)
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(signed))) as archive:
            text = archive.extractfile('APKINDEX').read().decode()
        records = list(map(fields, text.split('\n\n')))
        for recipe in lock['alpine_recipes']:
            if not any(r.get('o') == recipe['source'] and r.get('V') == recipe['version'] and r.get('c') == recipe['commit'] for r in records):
                raise ValueError('Recipe revision not authenticated by APKINDEX')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=pathlib.Path)
    parser.add_argument('--download', action='store_true', help='Download missing files only; never overwrite existing data')
    parser.add_argument('--provenance', action='store_true', help='Require sqv/OpenSSL signature and index checks')
    parser.add_argument('--debian-keyring', help='Existing trusted Debian archive keyring; never installed by this script')
    args = parser.parse_args()
    lock = json.loads(pathlib.Path(__file__).with_name('sources.lock.json').read_text())
    root = args.directory.resolve()
    if sum(r['bytes'] for r in lock['files']) > 800_000_000:
        raise ValueError('Acquisition exceeds bounded size')
    for row in lock['files']:
        relative = pathlib.PurePosixPath(row['file'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unsafe manifest path')
        path = root / row['file']
        if not path.resolve().is_relative_to(root):
            raise ValueError('Destination escapes source directory')
        if args.download and not path.exists():
            if not row['url'].startswith('https://'):
                raise ValueError('HTTPS source required')
            path.parent.mkdir(parents=True, exist_ok=True)
            with urllib.request.urlopen(row['url'], timeout=90) as response:
                data = response.read(row['bytes'] + 1)
            if len(data) != row['bytes'] or digest(data) != row['sha256']:
                raise ValueError('Downloaded bytes differ: ' + row['file'])
            with path.open('xb') as output:
                output.write(data)
    verify(root, lock, args.provenance, args.debian_keyring)
    print('Verified', len(lock['files']), 'pinned files; provenance:', args.provenance)


if __name__ == '__main__':
    main()
