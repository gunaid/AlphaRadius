"""Web's RADIUS health probe secret must match Core's web_container client.

deploy/local/build_and_start.sh writes a random RADIUS_HEALTH_SECRET to .env;
Web probes with it, so Core must use the same value for the Web client while
localhost keeps RADIUS_SECRET_DEFAULT for the container's own radtest check.

Isolated: runs only the clients.conf part of the Core entrypoint with bash in
a temporary directory; no FreeRADIUS, Docker or database.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / 'docker/freeradius/entrypoint.sh'


def clients_block():
    script = ENTRYPOINT.read_text(encoding='utf-8')
    head = script[script.index('DEFAULT_SECRET='):script.index('# 1. Write the clean SQL module')]
    start = script.index('# 2. Write clean clients.conf')
    end = script.index('\nEOF\n', start) + len('\nEOF\n')
    return head + script[start:end]


def render_clients(env):
    with tempfile.TemporaryDirectory() as folder:
        full_env = {'CONF_DIR': folder, 'PATH': '/usr/bin:/bin', **env}
        subprocess.run(['bash', '-c', clients_block()], env=full_env, check=True)
        text = (Path(folder) / 'clients.conf').read_text(encoding='utf-8')
    return {name: secret for name, secret in
            re.findall(r'client (\w+) \{.*?secret = (\S+)', text, flags=re.S)}


@unittest.skipUnless(shutil.which('bash'), 'bash is required')
class EntrypointClientsTests(unittest.TestCase):
    def test_web_client_uses_health_secret_and_localhost_keeps_default(self):
        secrets = render_clients({'RADIUS_SECRET_DEFAULT': 'fixture-default',
                                  'RADIUS_WEB_CLIENT_SECRET': 'fixture-health'})
        self.assertEqual(secrets['web_container'], 'fixture-health')
        self.assertEqual(secrets['localhost'], 'fixture-default')
        self.assertEqual(secrets['localhost_ipv6'], 'fixture-default')

    def test_web_client_falls_back_to_default_secret(self):
        secrets = render_clients({'RADIUS_SECRET_DEFAULT': 'fixture-default'})
        self.assertEqual(secrets['web_container'], 'fixture-default')


class ComposeWiringTests(unittest.TestCase):
    def test_core_receives_the_web_health_secret(self):
        for name in ('docker-compose.yml', 'docker-compose.production.yml'):
            compose = (ROOT / name).read_text(encoding='utf-8')
            core = compose[compose.index('\n  freeradius:\n'):compose.index('\n  wisp-web:\n')]
            web = compose[compose.index('\n  wisp-web:\n'):]
            self.assertIn('RADIUS_WEB_CLIENT_SECRET: ${RADIUS_HEALTH_SECRET:-max123}', core, name)
            self.assertIn('- RADIUS_HEALTH_SECRET=${RADIUS_HEALTH_SECRET:-max123}', web, name)


if __name__ == '__main__':
    unittest.main()
