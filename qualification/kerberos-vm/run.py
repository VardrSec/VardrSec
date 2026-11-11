#!/usr/bin/env python3
"""Bounded disposable VM qualification. Never changes host security policy."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import urllib.request

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BUILD_FILES = ('build-krb5.sh', 'krb5-CVE-2026-119079.patch',
               'krb5-keyring-test-diagnostic.patch', 'krb5-sequence-regression.c', 'Dockerfile')


def sha(path, algorithm='sha256'):
    h = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def download(url, destination, expected=None, algorithm='sha256', limit=500_000_000):
    if not url.startswith('https://'):
        raise ValueError('HTTPS required')
    size = 0
    with urllib.request.urlopen(url, timeout=90) as response, destination.open('xb') as output:
        while block := response.read(1024 * 1024):
            size += len(block)
            if size > limit:
                raise ValueError('Download exceeds bound')
            output.write(block)
    if expected and sha(destination, algorithm) != expected:
        raise ValueError('Pinned checksum mismatch: ' + destination.name)


def qemu_command(work, phase):
    if phase not in ('prepare', 'build'):
        raise ValueError('Unknown phase')
    # TCG requires no KVM permissions, kernel modules or security-policy changes.
    command = ['qemu-system-x86_64', '-machine', 'q35', '-accel', 'tcg,thread=multi',
               '-cpu', 'max', '-m', '4096', '-smp', '2', '-display', 'none',
               '-monitor', 'none', '-no-reboot', '-serial', f'file:{work / (phase + ".serial.log")}',
               '-drive', f'file={work / "guest.qcow2"},if=virtio,format=qcow2',
               '-drive', f'file={work / "output.img"},if=virtio,format=raw',
               '-drive', f'file={work / (phase + ".iso")},media=cdrom,format=raw,readonly=on',
               '-drive', f'file={work / "inputs.iso"},media=cdrom,format=raw,readonly=on']
    return command + ['-nic', 'user,model=virtio-net-pci' if phase == 'prepare' else 'none']


def extract(work, phase):
    target = work / ('result-' + phase)
    target.mkdir()
    # debugfs is read-only by default. Do not mount or execute guest output.
    run('debugfs', '-R', f'rdump / {target}', work / 'output.img')
    verdict = target / 'vm' / (phase + '.exit')
    if not verdict.is_file() or verdict.read_text().strip() != '0':
        raise RuntimeError(f'{phase} guest did not report success; retained logs are authoritative')
    return target


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work', type=Path, required=True, help='Fresh dedicated directory')
    p.add_argument('--source-only', action='store_true', help='Build context without Git metadata; record input hash, not a claimed revision')
    args = p.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    inputs = json.loads((HERE / 'inputs.json').read_text())
    download(inputs['image_url'], work / 'base.qcow2', inputs['image_sha512'], 'sha512')
    download(inputs['manifest_url'], work / 'official-SHA512SUMS', limit=100_000)
    expected_line = inputs['image_sha512'] + '  ' + inputs['image_url'].rsplit('/', 1)[1]
    if expected_line not in (work / 'official-SHA512SUMS').read_text().splitlines():
        raise ValueError('Official manifest no longer contains reviewed image pin')
    (work / 'qualification-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    source = work / 'input'
    build = source / 'build'
    build.mkdir(parents=True)
    for name, digest in inputs['sources'].items():
        download(inputs['source_base'] + name, build / name, digest, limit=30_000_000)
    for name in BUILD_FILES:
        shutil.copyfile(REPO / 'db' / name, build / name)
    hashes = ''.join(f'{sha(file)}  {file.name}\n' for file in sorted(build.iterdir()))
    (build / 'INPUT-SHA256SUMS').write_text(hashes)
    shutil.copyfile(HERE / 'guest.sh', source / 'guest.sh')
    shutil.copyfile(HERE / 'inputs.json', source / 'inputs.json')
    revision = ('source-inputs-sha256:' + hashlib.sha256(hashes.encode()).hexdigest() if args.source_only
                else subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip())
    (source / 'revision.txt').write_text(revision + '\n')
    run('xorriso', '-as', 'mkisofs', '-quiet', '-V', 'QUALINPUT', '-J', '-R', '-o', work / 'inputs.iso', source)
    run('qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', work / 'base.qcow2', work / 'guest.qcow2', '24G')
    with (work / 'output.img').open('xb') as output:
        output.truncate(512 * 1024 * 1024)
    run('mkfs.ext4', '-q', '-F', '-L', 'VMOUT', work / 'output.img')
    for phase, seconds in [('prepare', 1800), ('build', 7200)]:
        cloud = work / (phase + '-cloud')
        cloud.mkdir()
        (cloud / 'meta-data').write_text(f'instance-id: vardr-krb-{phase}\nlocal-hostname: krb-qualification\n')
        user = '#cloud-config\nssh_pwauth: false\nruncmd:\n  - [mkdir, -p, /mnt/bootstrap]\n  - [mount, -o, ro, /dev/disk/by-label/QUALINPUT, /mnt/bootstrap]\n  - [bash, /mnt/bootstrap/guest.sh, ' + phase + ']\n'
        (cloud / 'user-data').write_text(user)
        run('cloud-localds', work / (phase + '.iso'), cloud / 'user-data', cloud / 'meta-data')
        command = qemu_command(work, phase)
        (work / (phase + '-command.json')).write_text(json.dumps(command, indent=2) + '\n')
        try:
            run(*command, timeout=seconds)
        finally:
            # Preserve even failed-boot logs. Success requires explicit guest exit.
            result = extract(work, phase)
        if phase == 'prepare':
            (work / 'prepared-disk.sha256').write_text(sha(work / 'guest.qcow2') + '\n')
    (work / 'verified.json').write_text(json.dumps({
        'schema': 1, 'distribution_commit': None if args.source_only else revision,
        'source_inputs_sha256': hashlib.sha256(hashes.encode()).hexdigest(),
        'image_sha512': inputs['image_sha512'],
        'prepared_disk_sha256': (work / 'prepared-disk.sha256').read_text().strip(),
        'full_debian_package_build_passed': True, 'offline_build_boot': True,
        'release_clearance': False, 'independent_reproducibility': False,
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
