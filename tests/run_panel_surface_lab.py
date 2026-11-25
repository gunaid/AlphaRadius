"""Real application on two ports: subscriber portal on PORT, admin on ADMIN_PORT.

Needs a disposable MariaDB named panel_fixture with the application schema
(e.g. ``mysql panel_fixture < database/schema_mysql.sql``):

    DB_TYPE=mysql DB_HOST=127.0.0.1 DB_USER=... DB_PASSWORD=... DB_NAME=panel_fixture \\
        python tests/run_panel_surface_lab.py --run

Builds the full Flask factory (license stubbed as active, background workers
not started), serves it with Waitress on two loopback ports exactly as run.py
does, and checks real routes and templates on both sides. Read-only.
"""
import os
import socket
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    if sys.argv[1:] != ['--run'] or os.environ.get('DB_NAME') != 'panel_fixture':
        raise SystemExit('Only panel_fixture with --run is allowed')
    portal, admin = free_port(), free_port()
    os.environ.update(PORT=str(portal), ADMIN_PORT=str(admin))
    sys.path.insert(0, str(ROOT))

    start = threading.Thread.start
    threading.Thread.start = lambda self: None          # no workers while building the app
    import services.license_guard_service as lic
    active = lambda *a, **k: dict(valid=True, status='active', features={}, limits={}, plan_tier='Synthetic')
    lic.get_active_license_status = active
    lic.has_license_feature = lambda *a, **k: True
    import core.license_feature_policy as feature
    feature.verified_state = active
    from web import create_app
    app = create_app({'TESTING': True})
    threading.Thread.start = start

    from waitress import create_server
    server = create_server(app, listen=f'127.0.0.1:{portal} 127.0.0.1:{admin}', threads=4)
    threading.Thread(target=server.run, daemon=True).start()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(NoRedirect)

    def fetch(port, path, headers=None):
        request = urllib.request.Request(f'http://127.0.0.1:{port}{path}', headers=headers or {})
        try:
            with opener.open(request, timeout=20) as response:
                return response.status, response.headers, response.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read().decode('utf-8', 'replace')

    class Cases(unittest.TestCase):
        def test_01_factory_reads_admin_port(self):
            self.assertEqual(app.config['ADMIN_PORT'], admin)

        def test_02_portal_root_opens_subscriber_login(self):
            status, headers, _ = fetch(portal, '/')
            self.assertEqual(status, 302)
            self.assertTrue(headers['Location'].endswith('/user/login'))
            status, _, html = fetch(portal, '/user/login')
            self.assertEqual(status, 200)
            self.assertIn('user/login', html)
            self.assertNotIn('/settings', html)
            self.assertEqual(fetch(portal, '/static/brand/product-brand.css')[0], 200)

        def test_03_portal_hides_admin(self):
            for path in ('/login', '/login/verify', '/settings', '/settings/license', '/vouchers', '/api/coa/status', '/managers'):
                status, _, html = fetch(portal, path)
                self.assertEqual(status, 404, path)
                self.assertIn('بوابة المشتركين', html)
            for headers in ({'Host': f'127.0.0.1:{admin}'}, {'X-Forwarded-Port': str(admin)}):
                self.assertEqual(fetch(portal, '/login', headers)[0], 404)

        def test_04_admin_port_is_the_full_panel(self):
            status, _, html = fetch(admin, '/login')
            self.assertEqual(status, 200)
            self.assertIn('password', html)
            status, headers, _ = fetch(admin, '/')
            self.assertEqual(status, 302)
            self.assertIn('/login', headers['Location'])
            self.assertEqual(fetch(admin, '/user/login')[0], 200)

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
    server.close()
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
