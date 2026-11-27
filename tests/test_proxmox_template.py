"""Proxmox template scripts (deploy/proxmox): isolated, with a stub docker.

The full flow was also run against a real Docker daemon with stand-in images
(see docs/PROXMOX_TEMPLATE_20261127.md); these cases keep the guards honest
without Docker: refusals, sealing, secrets, image list and compose defaults.
"""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PREPARE = ROOT / 'deploy/proxmox/prepare_template.sh'
FIRST_BOOT = ROOT / 'deploy/proxmox/first_boot.sh'
IMAGES = ('ALPHA_WEB_IMAGE=gunaid/alpha-radius-web:t\nALPHA_CORE_IMAGE=gunaid/alpha-radius-core:t\n'
          'ALPHA_L2TP_IMAGE=gunaid/alpha-radius-l2tp:t\nALPHA_DB_IMAGE=mariadb:10.11\n'
          'ALPHA_AUTOHEAL_IMAGE=willfarrell/autoheal:latest\n')

STUB_DOCKER = r'''#!/bin/bash
echo "docker $*" >> "$STUB_LOG"
case "$1" in
  info) exit 0 ;;
  ps) printf '%s' "${STUB_CONTAINERS:-}"; exit 0 ;;
  volume) [[ -n "${STUB_VOLUME:-}" ]] && exit 0; exit 1 ;;
  image) [[ " ${STUB_MISSING:-} " == *" ${3} "* ]] && exit 1; exit 0 ;;
  compose|exec) exit 0 ;;
esac
exit 0
'''


@unittest.skipUnless(shutil.which('bash') and os.geteuid() == 0, 'needs bash and root (scripts require root)')
class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        (self.bin / 'docker').write_text(STUB_DOCKER)
        for name in ('apt-get', 'systemctl', 'nginx', 'timedatectl', 'sysctl', 'modprobe', 'ip', 'ufw',
                     'systemd-machine-id-setup', 'ssh-keygen'):
            (self.bin / name).write_text('#!/bin/sh\necho "%s $*" >> "$STUB_LOG"\nexit 0\n' % name)
        for path in self.bin.iterdir():
            path.chmod(path.stat().st_mode | stat.S_IEXEC)
        self.opt, self.etc = self.tmp / 'opt', self.tmp / 'etc'
        (self.etc / 'ssh').mkdir(parents=True)
        (self.etc / 'machine-id').write_text('0123456789abcdef0123456789abcdef\n')
        for key in ('ssh_host_ed25519_key', 'ssh_host_rsa_key'):
            (self.etc / 'ssh' / key).write_text('k')
        (self.tmp / 'uuid-template').write_text('11111111-0000-0000-0000-template\n')
        (self.tmp / 'uuid-customer').write_text('22222222-0000-0000-0000-customer\n')
        self.opt.mkdir()
        (self.opt / 'runtime-release.env').write_text(IMAGES)
        shutil.copy(ROOT / 'docker-compose.production.yml', self.opt)
        shutil.copy(FIRST_BOOT, self.opt / 'first-boot.sh')
        (self.opt / 'storage').mkdir()
        (self.opt / '.template-build-complete').write_text('2026-11-27T00:00:00Z\n')
        self.log = self.tmp / 'log'
        self.log.write_text('')

    def env(self, **extra):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", INSTALL_DIR=str(self.opt),
                   ALPHA_ETC=str(self.etc), ALPHA_DMI_UUID_FILE=str(self.tmp / 'uuid-template'),
                   ALPHA_DBUS_MACHINE_ID=str(self.tmp / 'dbus-id'),
                   SIGNING_KEY=str(self.tmp / 'keys/runtime-signing-private.pem'), STUB_LOG=str(self.log),
                   ALPHA_CHECKOUT_SEARCH=str(self.tmp / 'home'))
        env.update(extra)
        return env

    def run_script(self, script, *args, stdin='', **extra):
        return subprocess.run(['bash', str(script), *args], input=stdin, capture_output=True, text=True,
                              env=self.env(**extra), cwd=str(ROOT), timeout=60)

    def seal(self, *args, stdin=''):
        return self.run_script(PREPARE, 'seal', *args, stdin=stdin)

    # ------------------------------------------------------------------ seal
    def test_seal_refuses_while_signing_key_is_on_the_vm(self):
        key = self.tmp / 'keys/runtime-signing-private.pem'
        key.parent.mkdir()
        key.write_text('secret')
        result = self.seal('--yes')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Private key still on this VM', result.stderr)
        self.assertEqual((self.etc / 'machine-id').read_text().strip(), '0123456789abcdef0123456789abcdef')

    def test_seal_refuses_a_vm_that_ran_the_system(self):
        for name, extra in (('.env', {}), ('storage/instance_id', {})):
            path = self.opt / name
            path.write_text('x')
            self.assertIn('already ran ALPHA RADIUS', self.seal('--yes').stderr)
            path.unlink()
        result = self.run_script(PREPARE, 'seal', '--yes', STUB_CONTAINERS='alpha_radius_db\n')
        self.assertIn('alpha_radius_db', result.stderr)
        result = self.run_script(PREPARE, 'seal', '--yes', STUB_VOLUME='1')
        self.assertIn('volume alpha-radius_mariadb_data', result.stderr)

    def test_seal_refuses_while_a_source_checkout_exists(self):
        git = self.tmp / 'home/max/AlphaRadius/.git'
        git.mkdir(parents=True)
        (git / 'config').write_text('[remote "origin"]\n\turl = https://github.com/gunaid/AlphaRadius.git\n')
        result = self.seal('--yes')
        self.assertIn('Source checkout still on this VM: ' + str(git.parent), result.stderr)
        (git / 'config').write_text('[remote "origin"]\n\turl = https://example.org/other.git\n')
        self.assertEqual(self.seal('--yes').returncode, 0, 'unrelated repositories are fine')

    def test_seal_requires_a_finished_build(self):
        (self.opt / '.template-build-complete').unlink()
        result = self.seal('--yes')
        self.assertIn('build stage did not finish', result.stderr)
        self.assertEqual((self.etc / 'machine-id').read_text().strip(), '0123456789abcdef0123456789abcdef')

    def test_seal_requires_every_image_including_l2tp(self):
        result = self.run_script(PREPARE, 'seal', '--yes', STUB_MISSING='gunaid/alpha-radius-l2tp:t')
        self.assertIn('Images missing (rerun build): gunaid/alpha-radius-l2tp:t', result.stderr)

    def test_seal_needs_typed_confirmation_then_removes_identity(self):
        self.assertIn('Cancelled', self.seal(stdin='no\n').stderr)
        (self.tmp / 'dbus-id').write_text('own')
        result = self.seal(stdin='SEAL\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.etc / 'machine-id').read_text(), '')
        self.assertEqual(list((self.etc / 'ssh').iterdir()), [])
        self.assertEqual(os.readlink(self.tmp / 'dbus-id'), '/etc/machine-id')
        self.assertEqual(len((self.opt / '.template-vm-uuid.sha256').read_text().strip()), 64)
        self.assertIn('docker builder prune -af', self.log.read_text(), 'build cache with sources is dropped')

    # ------------------------------------------------------------ first boot
    def sealed(self):
        self.assertEqual(self.seal('--yes').returncode, 0)

    def boot(self, *args, uuid='uuid-customer', **extra):
        return self.run_script(self.opt / 'first-boot.sh', *args,
                               ALPHA_DMI_UUID_FILE=str(self.tmp / uuid), **extra)

    def test_first_boot_refuses_the_template_uuid(self):
        self.sealed()
        result = self.boot('--yes', uuid='uuid-template')
        self.assertIn("still has the template's UUID", result.stderr)
        self.assertFalse((self.opt / '.env').exists())

    def test_first_boot_argument_checks(self):
        for args, message in ((('--admin-port', '80'), '1024 to 65535'), (('--admin-port', '5090'), 'already used'),
                              (('--admin-port', 'x'), '1024 to 65535'), (('--timezone', 'a;b'), 'Invalid --timezone'),
                              (('--bogus',), 'Usage')):
            result = self.boot(*args, '--yes')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr, args)

    def test_first_boot_refuses_copied_or_existing_installations(self):
        self.sealed()
        for name in ('.env', '.first-boot-done', 'storage/instance_id', 'storage/machine_id'):
            (self.opt / name).write_text('x')
            self.assertNotEqual(self.boot('--yes').returncode, 0, name)
            (self.opt / name).unlink()
        self.assertIn('Images missing', self.boot('--yes', STUB_MISSING='mariadb:10.11').stderr)
        self.assertIn('Cancelled', self.run_script(self.opt / 'first-boot.sh', stdin='no\n',
                                                   ALPHA_DMI_UUID_FILE=str(self.tmp / 'uuid-customer')).stderr)

    def test_first_boot_writes_unique_secrets_and_starts_offline(self):
        self.sealed()
        result = self.boot('--admin-port', '43333', '--timezone', 'Asia/Aden', '--yes')
        self.assertEqual(result.returncode, 0, result.stderr)
        env = dict(line.split('=', 1) for line in (self.opt / '.env').read_text().splitlines())
        self.assertEqual(sorted(env), ['ALPHA_ADMIN_PORT', 'ALPHA_DB_PASSWORD', 'ALPHA_DB_ROOT_PASSWORD',
                                       'RADIUS_HEALTH_SECRET', 'SYSTEM_TIMEZONE'])
        self.assertEqual(env['ALPHA_ADMIN_PORT'], '43333')
        self.assertRegex(env['ALPHA_DB_PASSWORD'], r'^[0-9a-f]{48}$')
        self.assertNotEqual(env['ALPHA_DB_PASSWORD'], env['ALPHA_DB_ROOT_PASSWORD'])
        self.assertEqual(stat.S_IMODE((self.opt / '.env').stat().st_mode), 0o600)
        log = self.log.read_text()
        ups = [line for line in log.splitlines() if line.startswith('docker compose') and ' up ' in line]
        self.assertEqual(len(ups), 3)
        self.assertTrue(all('--pull never' in line for line in ups), ups)
        self.assertIn('systemd-machine-id-setup --root=', log, 'empty machine-id after seal is recreated')
        self.assertIn('ssh-keygen -A -f', log)
        self.assertTrue((self.opt / '.first-boot-done').exists())
        self.assertIn('http://', result.stdout)
        self.assertIn(':43333', result.stdout)

        other = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, other)
        shutil.copytree(self.opt, other / 'opt')
        for name in ('.env', '.first-boot-done'):
            (other / 'opt' / name).unlink()
        second = self.run_script(other / 'opt/first-boot.sh', '--yes', INSTALL_DIR=str(other / 'opt'),
                                 ALPHA_DMI_UUID_FILE=str(self.tmp / 'uuid-customer'))
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual((other / 'opt/.env').read_text(), (self.opt / '.env').read_text(), 'secrets differ per VM')


class ComposeAndFilesTests(unittest.TestCase):
    def test_compose_defaults_unchanged_for_existing_installs(self):
        text = (ROOT / 'docker-compose.production.yml').read_text(encoding='utf-8')
        compose = yaml.safe_load(text)
        db = compose['services']['mariadb']['environment']
        self.assertEqual(db['MYSQL_ROOT_PASSWORD'], '${ALPHA_DB_ROOT_PASSWORD:-rootpass}')
        self.assertEqual(db['MYSQL_PASSWORD'], '${ALPHA_DB_PASSWORD:-radpass}')
        self.assertEqual(compose['services']['freeradius']['environment']['DB_PASSWORD'], '${ALPHA_DB_PASSWORD:-radpass}')
        self.assertIn('DB_PASSWORD=${ALPHA_DB_PASSWORD:-radpass}', compose['services']['wisp-web']['environment'])
        self.assertNotIn(': radpass', text)
        self.assertNotIn('=radpass\n', text)

    def test_scripts_are_valid_bash_and_independent(self):
        for script in (PREPARE, FIRST_BOOT):
            subprocess.run(['bash', '-n', str(script)], check=True)
        for legacy in ('install.sh', 'deploy/local/build_and_start.sh'):
            self.assertNotIn('proxmox', (ROOT / legacy).read_text(encoding='utf-8'))
        prepare = PREPARE.read_text(encoding='utf-8')
        self.assertIn('install -m700 "$SRC/deploy/proxmox/first_boot.sh" "$INSTALL_DIR/first-boot.sh"', prepare)
        self.assertIn('install -m700 "$SRC/deploy/proxmox/prepare_template.sh" "$INSTALL_DIR/prepare-template.sh"', prepare)
        self.assertIn('--secret id=runtime_signing_key', prepare)
        self.assertIn('install -Dm755 "$SRC/deploy/ubuntu/alphaip" "${ALPHA_BIN_DIR:-/usr/local/bin}/alphaip"', prepare)


if __name__ == '__main__':
    unittest.main()
