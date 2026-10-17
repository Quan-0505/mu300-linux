import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('f50_build', HERE / 'build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class UpgradeContracts(unittest.TestCase):
    def test_rust_daed_candidate_and_state_migration_contract(self):
        service = (HERE / 'overlay/etc/init.d/daed').read_text()
        self.assertEqual(build.VERSION, '3.2.1')
        self.assertIn('v2026.10.17.5', build.PUBLIC['kernel-5.4.tar.gz'][0])
        self.assertIn('state migrate --from-wing-db', service)
        self.assertIn('--to "$state_db"', service)
        self.assertIn('NETNS_LINK=veth', service)
        self.assertNotIn('DAE_FORCE_VETH', service)
        self.assertNotIn('DAE_DISABLE_REDIRECT_PEER', service)

    def test_running_mainline_is_not_silently_replaced_with_vendor_kernel(self):
        source = (HERE.parent / 'rootfs/overlay/opt/mu300/bin/mu300-update').read_text()
        function = source[source.index('kernel_choice() {'):source.index('\nkernel_asset()')]
        command = 'KERNEL_CHOICE=/nonexistent/f50-test; KERNELS="5.4 6.18 7.2"; uname() { echo 6.18.55; }; ' + function + '\nkernel_choice'
        self.assertEqual(subprocess.check_output(['sh', '-c', command], text=True).strip(), '6.18')

    def test_config_and_manual_software_survive_update(self):
        updater = HERE.parent / 'rootfs/overlay/opt/mu300/bin/mu300-update'
        # Execute the real keep_list() in a shell, rather than checking comments.
        source = updater.read_text()
        function = source[source.index('keep_list() {'):source.index('# vendor files that')]
        result = subprocess.check_output(['sh', '-c', function + '\nkeep_list openwrt'], text=True)
        keep = result.split()
        for name in ['etc/config', 'etc/dropbear', 'etc/crontabs', 'etc/daed', 'etc/daed-kdae', 'etc/kixdns', 'usr/local', 'etc/init.d/kixdns', 'etc/samba', 'var/lib/samba', 'srv']:
            self.assertIn(name, keep)
        self.assertNotIn('usr/bin/daed', keep)  # new binary must not be overwritten by the old one
        self.assertNotIn('etc/init.d/daed', keep)  # preserve data, use the image's service

    def test_repack_keeps_file_owners_symlinks_and_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, output = Path(tmp) / 'base.tgz', Path(tmp) / 'output.tgz'
            with tarfile.open(base, 'w:gz') as archive:
                for name, data in [('etc/openwrt_release', b'version'), ('etc/shadow', b'root:*:0:0:99999:7:::\n')]:
                    member = tarfile.TarInfo('./' + name)
                    member.uid, member.gid, member.mode, member.size = 0, 42, 0o640, len(data)
                    archive.addfile(member, io.BytesIO(data))
                member = tarfile.TarInfo('./sbin/init')
                member.type, member.linkname = tarfile.SYMTYPE, '../bin/busybox'
                archive.addfile(member)
            with patch.object(build, 'payload', return_value=iter([('usr/bin/daed', b'new-binary', 0o755)])):
                build.rootfs(base, output)
            with tarfile.open(output) as archive:
                self.assertEqual(archive.getmember('./etc/shadow').gid, 42)
                self.assertEqual(archive.getmember('./etc/shadow').mode, 0o640)
                self.assertEqual(archive.getmember('./sbin/init').linkname, '../bin/busybox')
                self.assertEqual(archive.extractfile('./usr/bin/daed').read(), b'new-binary')

    def test_private_state_is_refused(self):
        for name in ['etc/daed/wing.db', 'usr/local/owjdxb/.dmac', 'root/.ssh/id_ed25519', 'etc/dropbear/dropbear_rsa_host_key']:
            with self.subTest(name=name), self.assertRaises(AssertionError):
                build.privacy(name)


if __name__ == '__main__':
    unittest.main()
