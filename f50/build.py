#!/usr/bin/env python3
"""Build a public, state-free F50 update payload; never write to a device."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import struct
import subprocess
import sys
import tarfile
import time

TOP = Path(__file__).resolve().parents[1]
WORK = TOP / 'work/f50-addons'
INPUTS = TOP / 'work/f50-inputs'
VERSION = '3.2.1'
RUST_DAED_REPOSITORY = 'https://github.com/Quan-0505/rust-daed.git'
RUST_DAED_REVISION = '7b1d18772789be988c933dc5e18fdb5411a00857'
PUBLIC = {
    'kernel-5.4.tar.gz': (
        'https://github.com/dikeckaan/mu300-linux/releases/download/v2026.10.17.5/mu300-kernel.tar.gz',
        'dbfd241f2d8b45bd21ee6026f093034d1b36117f0bf5446fcd3eef638470f489'),
    'public-rootfs.tar.gz': (
        'https://github.com/dikeckaan/mu300-linux/releases/download/v2026.10.17.5/mu300-openwrt-luci-rootfs.tar.gz',
        'efcb643c327e4ffbfc6665f969b36d40e5d5be89a2b32cb5d062e4cda0cbbe92'),
    'nodebaby.tgz': (
        'https://cdn.ionewu.com/upgrade/jdxb/owjdxb_openwrt_arm64_4.3.5-734.tgz',
        'c2c1853eac004ae3699a8f3beba3331afc42aca1878acd2c7945a5658deea702'),
}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def download(url, dest, expected):
    if dest.is_file() and sha(dest) == expected:
        return
    part = dest.with_suffix(dest.suffix + '.part')
    run('curl', '-fL', '--retry', '3', '--connect-timeout', '20', '--max-time', '300', '-o', str(part), url)
    if sha(part) != expected:
        raise ValueError('Public payload checksum differs: ' + dest.name)
    part.replace(dest)


def inputs():
    INPUTS.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    for name, (url, digest) in PUBLIC.items():
        try:
            download(url, INPUTS / name, digest)
        except subprocess.CalledProcessError:
            if name != 'nodebaby.tgz':
                raise
            download('https://github.com/Quan-0505/e5-linux/releases/download/build-inputs/owjdxb_openwrt_arm64_4.3.5-734.tgz', INPUTS / name, digest)
    with tarfile.open(INPUTS / 'kernel-5.4.tar.gz') as source:
        for member in source:
            name = member.name.removeprefix('./')
            target = None
            if member.isfile() and name.startswith('modules/') and name.endswith('.ko'):
                target = 'out/' + name
            elif name in ['modules.builtin', 'modules.builtin.modinfo']:
                target = 'out/' + name
            elif name == 'busybox':
                target = 'busybox'
            elif name == 'logdw':
                target = 'tools/logdw/logdw'
            if target:
                path = INPUTS / target
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(source.extractfile(member).read())
                path.chmod(member.mode & 0o777)
    helpers = {
        'opt/mu300/bin/mu300-bt-init': 'tools/bt-init/mu300-bt-init',
        'opt/mu300/bin/mu300-keys': 'tools/keys/mu300-keys',
    }
    with tarfile.open(INPUTS / 'public-rootfs.tar.gz') as source:
        for member in source:
            name = member.name.removeprefix('./')
            if name in helpers:
                assert member.isfile()
                path = INPUTS / helpers[name]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(source.extractfile(member).read())
                path.chmod(0o755)
    for path in helpers.values():
        assert (INPUTS / path).stat().st_size > 10000, path


def kernel_check(folder):
    config = (folder / 'kernel.config').read_text().splitlines()
    for key in ['BPF', 'BPF_SYSCALL', 'BPF_JIT', 'DEBUG_INFO_BTF', 'VETH', 'NET_CLS_BPF', 'NET_CLS_ACT', 'NET_SCH_INGRESS', 'TUN']:
        assert f'CONFIG_{key}=y' in config, key
    assert any(line in config for line in ['CONFIG_NET_ACT_BPF=y', 'CONFIG_NET_ACT_BPF=m'])
    if 'CONFIG_NET_ACT_BPF=m' in config:
        assert (folder / 'modules/act_bpf.ko').is_file()
    run('sha256sum', '--check', 'kernel.sha256', cwd=folder)
    run('sha256sum', '--check', 'modules.sha256', cwd=folder, stdout=subprocess.DEVNULL)
    assert b'Linux version 6.18.56' in (folder / 'Image').read_bytes()


def source_tree():
    return subprocess.check_output(['git', 'rev-parse', 'HEAD:upstream'], cwd=TOP, text=True).strip()


def kernel_attest(folder):
    kernel_check(folder)
    proof = folder / 'source-tree.git'
    if proof.exists():
        assert proof.read_text().strip() == source_tree(), 'Cached kernel source tree differs'
    proof.write_text(source_tree() + '\n')


def kernel_rebind(folder):
    # Different checkout jobs have different mtimes. First prove the artifact
    # matches the exact upstream Git tree and every recorded binary hash.
    assert (folder / 'source-tree.git').read_text().strip() == source_tree(), 'Kernel/source provenance mismatch'
    kernel_check(folder)
    latest = max(p.stat().st_mtime for p in (TOP / 'upstream/modules').rglob('*') if p.is_file())
    stamp = max(latest, time.time()) + 1
    for module in (folder / 'modules').glob('*.ko'):
        os.utime(module, (stamp, stamp))
    print('Cross-job module timestamps normalized after source-tree and binary hash verification')


def payload():
    binary = (WORK / 'daed').read_bytes()
    assert binary[:5] == b'\x7fELF\x02' and struct.unpack('<H', binary[18:20])[0] == 183
    assert f'version=v{VERSION}'.encode() in binary, 'Unexpected Rust daed version'
    yield 'usr/bin/daed', binary, 0o755
    for name in ['geoip.dat', 'geosite.dat']:
        data = (WORK / name).read_bytes()
        assert len(data) > 100000 and not data.lstrip().startswith(b'<'), 'Invalid Rust geodata: ' + name
        yield 'usr/share/daed/' + name, data, 0o644
    web = WORK / 'web'
    assert (web / 'index.html').is_file(), 'Rust DaedNext UI missing'
    for path in sorted(web.rglob('*')):
        if path.is_file():
            yield 'usr/share/daed/web/' + path.relative_to(web).as_posix(), path.read_bytes(), 0o644
    assert sha(INPUTS / 'nodebaby.tgz') == PUBLIC['nodebaby.tgz'][1]
    with tarfile.open(INPUTS / 'nodebaby.tgz') as source:
        for member in source:
            name = member.name.removeprefix('./')
            parts = PurePosixPath(name).parts
            assert parts and parts[0] == 'owjdxb' and '..' not in parts and not name.startswith('/')
            assert member.isfile() or member.isdir()
            if member.isdir():
                continue
            assert parts[-1] not in ['wing.db', 'daed.db', '.dmac', '.dmacv1']
            data = source.extractfile(member).read()
            if name == 'owjdxb/start.sh':
                assert data.count(b'    export SPECIAL_IFACE_NAME=lo\n') == 1
                data = data.replace(b'    export SPECIAL_IFACE_NAME=lo\n', b'')
            yield 'usr/local/' + name, data, (0o755 if member.mode & 0o111 or name.endswith('.sh') else 0o644)
    for path in sorted((TOP / 'f50/overlay').rglob('*')):
        if path.is_file():
            name = path.relative_to(TOP / 'f50/overlay').as_posix()
            yield name, path.read_bytes(), (0o755 if name.startswith(('etc/init.d/', 'usr/libexec/')) else 0o644)


def privacy(name):
    p = PurePosixPath(name)
    assert not name.startswith(('etc/daed/', 'etc/daed-kdae/', 'etc/kixdns/', 'opt/mu300/android/system/lib', 'opt/mu300/android/vendor/')), name
    assert p.name not in {'wing.db', 'daed.db', '.dmac', '.dmacv1', 'id_rsa', 'id_ed25519'}, name
    assert not name.startswith(('etc/dropbear/dropbear_', 'etc/ssh/ssh_host_')), name
    assert not name.startswith(('root/.ssh/', 'home/')), name


def rootfs(source_path, destination):
    additions = {name: (data, mode) for name, data, mode in payload()}
    for name, start in [('daed', 95), ('owjdxb', 96)]:
        additions[f'etc/rc.d/S{start}{name}'] = (None, '../init.d/' + name)
        additions[f'etc/rc.d/K10{name}'] = (None, '../init.d/' + name)
    with tarfile.open(source_path) as src, tarfile.open(destination, 'w:gz') as dst:
        seen = set()
        for member in src:
            name = member.name.removeprefix('./')
            privacy(name)
            if name in additions:
                continue
            dst.addfile(member, src.extractfile(member) if member.isfile() else None)
            seen.add(name)
        assert 'sbin/init' in seen and 'etc/openwrt_release' in seen
        for name, (data, mode) in additions.items():
            privacy(name)
            member = tarfile.TarInfo('./' + name)
            member.uid = member.gid = 0
            member.uname = member.gname = 'root'
            if data is None:
                member.type = tarfile.SYMTYPE
                member.linkname = mode
                member.mode = 0o777
                dst.addfile(member)
            else:
                member.size, member.mode = len(data), mode
                dst.addfile(member, io.BytesIO(data))
    with tarfile.open(destination) as check:
        names = {m.name.removeprefix('./'): m for m in check}
        for name, (data, mode) in additions.items():
            member = names[name]
            assert member.uid == member.gid == 0
            if data is not None:
                assert check.extractfile(member).read() == data and member.mode == mode
            else:
                assert member.issym() and member.linkname == mode
        print('Rootfs public payload, service links and file ownership verified')


def finalize_kernel(path):
    """Audit the LK wrapper and hash the actual shipped bytes, not the raw Image."""
    output = path.with_suffix('.verified.tmp')
    raw = TOP / 'upstream/out'
    raw_image = (raw / 'Image').read_bytes()
    hashes = {}
    shipped_modules = set()
    with tarfile.open(path) as source, tarfile.open(output, 'w:gz') as target:
        for member in source:
            name = member.name.removeprefix('./')
            if name in ['kernel.sha256', 'modules.sha256']:
                continue
            if not member.isfile():
                target.addfile(member)
                continue
            data = source.extractfile(member).read()
            if name == 'Image':
                assert data[56:60] == b'ARMd'
                assert struct.unpack_from('<I', data)[0] == 0x14060000
                assert struct.unpack_from('<Q', data, 8)[0] == 0x80000
                assert data[0x180000:] == raw_image, 'Packaged LK Image is not the compiled kernel'
            elif name == 'kernel.config':
                assert data == (raw / name).read_bytes()
            elif name.startswith('modules/') and name.endswith('.ko'):
                assert hashlib.sha256(data).hexdigest() == sha(raw / name), name
                shipped_modules.add(name)
            hashes[name] = hashlib.sha256(data).hexdigest()
            target.addfile(member, io.BytesIO(data))
        expected = {p.relative_to(raw).as_posix() for p in (raw / 'modules').glob('*.ko')}
        assert expected == shipped_modules
        assert {'Image', 'kernel.config', 'kernel.release', 'ramdisk-generic.lz4'} <= hashes.keys()
        for name, names in [('kernel.sha256', ['Image', 'kernel.config']),
                            ('modules.sha256', ['Image', 'kernel.config', *sorted(shipped_modules)])]:
            data = ''.join(f'{hashes[n]}  {n}\n' for n in names).encode()
            member = tarfile.TarInfo('./' + name)
            member.size, member.mode = len(data), 0o644
            target.addfile(member, io.BytesIO(data))
    output.replace(path)
    print('Actual packaged LK Image and', len(shipped_modules), 'matching modules verified')


def manifest(folder):
    run('git', 'diff', '--exit-code')
    kernel_check(TOP / 'upstream/out')
    finalize_kernel(folder / 'mu300-kernel-6.18.tar.gz')
    result = {
        'target': 'ZTE F50 / MU300', 'openwrt': '25.12.5', 'kernel': '6.18.56',
        'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'kernel_source_tree': source_tree(),
        'raw_kernel_image_sha256': sha(TOP / 'upstream/out/Image'),
        'upstream_release': 'dikeckaan/mu300-linux v2026.10.17.5',
        'upstream_release_commit': '19d071fea3ee649bcee240de3e2bd632578dccb5',
        'upstream_clean_tf_7_2_head': 'a8f36987378b5e6e3726bc5e2a5b0c84c4a739e2',
        'rust_daed_repository': RUST_DAED_REPOSITORY,
        'rust_daed_revision': RUST_DAED_REVISION,
        'rust_daed_version': VERSION,
        'rust_daed_binary_sha256': sha(WORK / 'daed'), 'nodebaby_version': '4.3.5-734',
        'public_inputs': {k: {'url': v[0], 'sha256': v[1]} for k, v in PUBLIC.items()},
        'run_id': os.environ.get('GITHUB_RUN_ID'), 'device_boot_tested': False,
        'device_flashing_performed': False, 'android_partition_reclaimed': False,
        'install_mode': 'existing-internal-rootfs-update-no-repartition',
        'private_device_files_in_release': False,
    }
    (folder / 'build.json').write_text(json.dumps(result, indent=2) + '\n')
    (folder / 'kernel.config').write_bytes((TOP / 'upstream/out/kernel.config').read_bytes())
    files = [p for p in sorted(folder.iterdir()) if p.is_file() and p.name != 'SHA256SUMS']
    (folder / 'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in files))


if __name__ == '__main__':
    command = sys.argv[1]
    if command == 'inputs':
        inputs()
    elif command == 'kernel-check':
        kernel_check(Path(sys.argv[2]))
    elif command == 'kernel-attest':
        kernel_attest(Path(sys.argv[2]))
    elif command == 'kernel-rebind':
        kernel_rebind(Path(sys.argv[2]))
    elif command == 'rootfs':
        rootfs(Path(sys.argv[2]), Path(sys.argv[3]))
    elif command == 'manifest':
        manifest(Path(sys.argv[2]))
    else:
        raise SystemExit('Unknown command: ' + command)
