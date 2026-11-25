"""Separate admin port: subscriber portal on the main port, admin panel on
ADMIN_PORT. Isolated: a small Flask app with the real guard, plus a real
two-socket Waitress server on loopback."""
import socket
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from flask import Flask, g, redirect

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from web import panel_surface  # noqa: E402

ADMIN = 43333


def build_app(admin):
    app = Flask(__name__)
    calls = []

    @app.before_request
    def admin_login_wall():          # stands in for the real auth hook
        calls.append('auth')

    panel_surface.install(app, admin)

    for rule, name in (('/', 'dashboard'), ('/login', 'login'), ('/settings', 'settings'),
                       ('/api/coa/status', 'coa'), ('/settings/license', 'license'),
                       ('/user', 'user_home'), ('/user/login', 'user_login'), ('/user/api/session_status', 'user_api'),
                       ('/api/hotspot/ping', 'hotspot'), ('/health', 'health'), ('/api/whatsapp/webhook', 'webhook'),
                       ('/users', 'admin_users'), ('/user-manager', 'admin_um')):
        app.add_url_rule(rule, name, (lambda n=name: f'{n}|{g.panel_surface}'), methods=['GET', 'POST'])
    return app, calls


def get(client, path, port, **kw):
    return client.get(path, environ_overrides={'SERVER_PORT': str(port)}, **kw)


class SettingTests(unittest.TestCase):
    def test_admin_port_parsing(self):
        self.assertIsNone(panel_surface.admin_port({}))
        for value in ('', ' ', 'abc', '0', '70000', '-1', '5090'):
            self.assertIsNone(panel_surface.admin_port({'ADMIN_PORT': value, 'PORT': '5090'}), value)
        self.assertIsNone(panel_surface.admin_port({'ADMIN_PORT': '8080', 'PORT': '8080'}))
        self.assertEqual(panel_surface.admin_port({'ADMIN_PORT': ' 43333 ', 'PORT': '5090'}), 43333)
        self.assertEqual(panel_surface.admin_port({'ADMIN_PORT': '43333'}), 43333)

    def test_surface(self):
        self.assertEqual(panel_surface.surface({'SERVER_PORT': '5090'}, None), 'all')
        self.assertEqual(panel_surface.surface({'SERVER_PORT': '43333'}, ADMIN), 'admin')
        self.assertEqual(panel_surface.surface({'SERVER_PORT': '5090'}, ADMIN), 'portal')
        self.assertEqual(panel_surface.surface({}, ADMIN), 'portal', 'unknown port is never admin')


class GuardTests(unittest.TestCase):
    def test_split_off_changes_nothing(self):
        app, _ = build_app(None)
        client = app.test_client()
        self.assertEqual(get(client, '/', 5090).get_data(as_text=True), 'dashboard|all')
        self.assertEqual(get(client, '/settings', 5090).get_data(as_text=True), 'settings|all')
        self.assertIsNone(app.config['ADMIN_PORT'])

    def test_portal_port(self):
        app, calls = build_app(ADMIN)
        client = app.test_client()
        response = get(client, '/', 5090)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/user/login'))
        self.assertEqual(calls, [], 'guard runs before every other hook')
        for path in ('/user', '/user/login', '/user/api/session_status', '/api/hotspot/ping', '/health', '/api/whatsapp/webhook'):
            response = get(client, path, 5090)
            self.assertEqual(response.status_code, 200, path)
            self.assertTrue(response.get_data(as_text=True).endswith('|portal'), path)
        for path in ('/login', '/settings', '/api/coa/status', '/settings/license', '/users', '/user-manager'):
            response = get(client, path, 5090)
            self.assertEqual(response.status_code, 404, path)
            self.assertIn('بوابة المشتركين', response.get_data(as_text=True))
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(client.post('/login', environ_overrides={'SERVER_PORT': '5090'}).status_code, 404)

    def test_forged_headers_do_not_reach_admin(self):
        app, _ = build_app(ADMIN)
        client = app.test_client()
        for headers in ({'Host': f'192.168.33.10:{ADMIN}'}, {'X-Forwarded-Port': str(ADMIN)},
                        {'X-Forwarded-Host': f'192.168.33.10:{ADMIN}', 'Forwarded': f'host=x:{ADMIN}'}):
            self.assertEqual(get(client, '/settings', 5090, headers=headers).status_code, 404, headers)

    def test_admin_port_keeps_everything(self):
        app, calls = build_app(ADMIN)
        client = app.test_client()
        self.assertEqual(get(client, '/', ADMIN).get_data(as_text=True), 'dashboard|admin')
        self.assertEqual(get(client, '/settings', ADMIN).get_data(as_text=True), 'settings|admin')
        self.assertEqual(get(client, '/user/login', ADMIN).get_data(as_text=True), 'user_login|admin')
        self.assertEqual(calls.count('auth'), 3)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class WaitressTests(unittest.TestCase):
    """The deciding fact: Waitress reports each socket's own port."""

    def test_two_sockets_one_app(self):
        from waitress import create_server
        portal_port, admin_port = free_port(), free_port()
        app, _ = build_app(admin_port)
        server = create_server(app, listen=f'127.0.0.1:{portal_port} 127.0.0.1:{admin_port}', threads=2)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        self.addCleanup(server.close)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(NoRedirect)

        def fetch(port, path, headers=None):
            request = urllib.request.Request(f'http://127.0.0.1:{port}{path}', headers=headers or {})
            try:
                with opener.open(request, timeout=5) as response:
                    return response.status, response.read().decode()
            except urllib.error.HTTPError as error:
                return error.code, error.headers.get('Location', '')

        self.assertEqual(fetch(admin_port, '/settings'), (200, 'settings|admin'))
        self.assertEqual(fetch(admin_port, '/'), (200, 'dashboard|admin'))
        self.assertEqual(fetch(portal_port, '/user/login'), (200, 'user_login|portal'))
        status, location = fetch(portal_port, '/')
        self.assertEqual(status, 302)
        self.assertTrue(location.endswith('/user/login'))
        self.assertEqual(fetch(portal_port, '/settings')[0], 404)
        self.assertEqual(fetch(portal_port, '/settings', {'Host': f'127.0.0.1:{admin_port}',
                                                          'X-Forwarded-Port': str(admin_port)})[0], 404)


class WiringTests(unittest.TestCase):
    def test_app_run_compose_and_probe(self):
        init = (ROOT / 'web/__init__.py').read_text(encoding='utf-8')
        self.assertLess(init.index('install_panel_surface(app)'), init.index('install_csrf(app'))
        run = (ROOT / 'run.py').read_text(encoding='utf-8')
        self.assertIn("admin = app.config.get('ADMIN_PORT')", run)
        self.assertIn('listen = f"{host}:{port} {host}:{admin}"', run)
        self.assertIn('serve(app, listen=listen, threads=8)', run)
        for name in ('docker-compose.yml', 'docker-compose.production.yml'):
            compose = (ROOT / name).read_text(encoding='utf-8')
            self.assertIn('- ADMIN_PORT=${ALPHA_ADMIN_PORT:-}', compose)
            self.assertIn('"${ALPHA_ADMIN_PORT:-43333}:${ALPHA_ADMIN_PORT:-43333}/tcp"', compose)
        probe = (ROOT / 'services/system_update_safety.py').read_text(encoding='utf-8')
        self.assertIn("os.environ.get('ADMIN_PORT') or", probe)
        for name in ('install.sh', 'deploy/local/build_and_start.sh'):
            self.assertIn('${admin_port:+$admin_port/tcp}', (ROOT / name).read_text(encoding='utf-8'))

    def test_webhook_address_drops_admin_port(self):
        from jinja2 import Environment
        source = (ROOT / 'web/templates/whatsapp/dashboard.html').read_text(encoding='utf-8')
        line = next(l for l in source.splitlines() if 'api/whatsapp/webhook' in l and 'panel_surface' in l).strip()
        template = Environment().from_string(line)

        class Request:
            scheme, host, host_url = 'http', f'192.168.33.10:{ADMIN}', f'http://192.168.33.10:{ADMIN}/'
        self.assertEqual(template.render(panel_surface='admin', request=Request), 'http://192.168.33.10/api/whatsapp/webhook')
        Request.host, Request.host_url = '192.168.33.10', 'http://192.168.33.10/'
        self.assertEqual(template.render(panel_surface='all', request=Request), 'http://192.168.33.10/api/whatsapp/webhook')


if __name__ == '__main__':
    unittest.main()
