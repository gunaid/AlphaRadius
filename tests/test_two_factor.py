"""Optional second factor for managers, asked only on a new device.

Isolated: no application import or database server. TOTP is checked against
the RFC 6238 SHA-1 vectors; storage runs on SQLite; the login routes are
loaded from source into a small Flask app with stubbed rendering.
"""
import ast
import base64
import sqlite3
import sys
import time
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from flask import Flask, flash, jsonify, redirect, request, session, url_for

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services import two_factor_service as tfa  # noqa: E402

RFC_SECRET = base64.b32encode(b'12345678901234567890').decode().rstrip('=')


class TotpTests(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for epoch, code in ((59, '287082'), (1111111109, '081804'), (1234567890, '005924'), (2000000000, '279037')):
            self.assertEqual(tfa.code_at(RFC_SECRET, epoch // 30), code)

    def test_window_replay_and_format(self):
        now = 1234567890
        code = tfa.code_at(RFC_SECRET, now // 30)
        self.assertEqual(tfa.matching_step(RFC_SECRET, code, now), now // 30)
        self.assertEqual(tfa.matching_step(RFC_SECRET, code[:3] + ' ' + code[3:], now + 30), now // 30, 'one step drift')
        self.assertIsNone(tfa.matching_step(RFC_SECRET, code, now + 90), 'too old')
        self.assertIsNone(tfa.matching_step(RFC_SECRET, code, now, last_step=now // 30), 'already used')
        for bad in ('', '12345', '1234567', 'abcdef', None):
            self.assertIsNone(tfa.matching_step(RFC_SECRET, bad, now))

    def test_secret_and_uri(self):
        secret = tfa.new_secret()
        self.assertEqual(len(secret), 32)
        self.assertEqual(len(base64.b32decode(secret)), 20)
        uri = tfa.provisioning_uri(secret, 'admin')
        self.assertTrue(uri.startswith('otpauth://totp/ALPHA%20RADIUS%3Aadmin?secret=' + secret))


class Storage(unittest.TestCase):
    """SQLite stand-in for database.db with the service's own SQLite DDL."""

    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        module = types.ModuleType('database.db')

        def run(sql, args=()):
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur
        module.query_one = lambda sql, args=(): (dict(r) if (r := run(sql, args).fetchone()) else None)
        module.query_all = lambda sql, args=(): [dict(r) for r in run(sql, args).fetchall()]
        module.execute_write = lambda sql, args=(): run(sql, args).lastrowid
        module.execute_update = lambda sql, args=(): run(sql, args).rowcount
        module.get_connection = lambda: types.SimpleNamespace(close=lambda: None)
        module.is_mysql_conn = lambda conn: False
        self.modules = patch.dict(sys.modules, {'database.db': module})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        tfa.ensure_tables()

    def enable(self, manager_id=1, now=None):
        secret = tfa.start_setup(manager_id)
        now = time.time() if now is None else now
        tfa.enable(manager_id, tfa.code_at(secret, int(now // 30)), now)
        return secret


class StorageTests(Storage):
    def test_setup_enable_consume_disable(self):
        self.assertFalse(tfa.is_enabled(1))
        secret = tfa.start_setup(1)
        with self.assertRaises(ValueError):
            tfa.enable(1, '000000' if tfa.code_at(secret, int(time.time() // 30)) != '000000' else '111111')
        now = time.time()
        tfa.enable(1, tfa.code_at(secret, int(now // 30)), now)
        self.assertTrue(tfa.is_enabled(1))
        with self.assertRaises(ValueError):
            tfa.start_setup(1)
        later = now + 60
        code = tfa.code_at(secret, int(later // 30))
        self.assertTrue(tfa.verify_code(1, code, later))
        self.assertFalse(tfa.verify_code(1, code, later), 'a code works once')
        token = tfa.trust_device(1, 'Firefox')
        self.assertTrue(tfa.is_trusted_device(1, token))
        self.assertFalse(tfa.is_trusted_device(2, token), 'device trust is per manager')
        tfa.disable(1)
        self.assertFalse(tfa.is_enabled(1))
        self.assertFalse(tfa.is_trusted_device(1, token))

    def test_expired_device_and_forget(self):
        self.enable()
        token = tfa.trust_device(1)
        self.db.execute("UPDATE wisp_manager_devices SET expires_at='2000-01-01 00:00:00'")
        self.assertFalse(tfa.is_trusted_device(1, token))
        fresh = tfa.trust_device(1)
        self.assertEqual(len(tfa.devices(1)), 1)
        self.assertEqual(tfa.forget_devices(1), 2)
        self.assertFalse(tfa.is_trusted_device(1, fresh))
        stored = self.db.execute('SELECT token_hash FROM wisp_manager_devices').fetchall()
        self.assertEqual(stored, [], 'forget removes all; raw tokens are never stored')

    def test_needs_second_factor(self):
        self.assertFalse(tfa.needs_second_factor(1, None), 'not enabled')
        self.enable()
        self.assertTrue(tfa.needs_second_factor(1, None))
        self.assertTrue(tfa.needs_second_factor(1, 'unknown'))
        self.assertFalse(tfa.needs_second_factor(1, tfa.trust_device(1)))


class LoginFlowTests(Storage):
    def setUp(self):
        super().setUp()
        self.db.execute("CREATE TABLE managers(id INTEGER PRIMARY KEY, username TEXT, full_name TEXT, password TEXT, is_active INT, role_id INT)")
        self.db.execute("INSERT INTO managers VALUES (1,'admin','Admin','pw',1,1),(2,'plain','Plain','pw',1,1)")
        self.db.commit()
        manager = lambda ident: dict(self.db.execute('SELECT * FROM managers WHERE id=?', (ident,)).fetchone(),
                                     role_name='Admin', role_code='superadmin', password_hash='pw')

        def query_one(sql, args=()):
            if 'FROM wisp_managers' in sql:
                row = self.db.execute('SELECT id FROM managers WHERE LOWER(username)=LOWER(?) OR id=?', (args[0], args[0])).fetchone()
                return manager(row['id']) if row else None
            return sys.modules['database.db'].query_one(sql, args)
        self.audit = []
        app = Flask('two_factor_test')
        app.secret_key = 'isolated-test'
        ns = dict(request=request, session=session, flash=flash, redirect=redirect, url_for=url_for, jsonify=jsonify,
                  render_template=lambda name, **kw: f'render:{name}', time=time,
                  datetime=__import__('datetime'), query_one=query_one, execute_write=lambda *a: None,
                  log_audit=lambda *a: self.audit.append(a[2]), get_current_manager=lambda: None,
                  verify_manager_password=lambda stored, raw: stored == raw)
        tree = ast.parse((ROOT / 'web/routes/auth.py').read_text(encoding='utf-8'))
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('login', '_complete_login', 'login_verify')]
        for node in nodes:
            node.decorator_list = []
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'auth', 'exec'), ns)
        app.add_url_rule('/login', 'login', ns['login'], methods=['GET', 'POST'])
        app.add_url_rule('/login/verify', 'login_verify', ns['login_verify'], methods=['GET', 'POST'])
        app.add_url_rule('/dashboard', 'dashboard', lambda: 'dashboard')
        self.client = app.test_client()

    def login(self, username='admin'):
        return self.client.post('/login', data={'username': username, 'password': 'pw'})

    def code(self, secret, offset=0):
        return tfa.code_at(secret, int((time.time() + offset) // 30))

    def test_manager_without_second_factor_logs_in_directly(self):
        response = self.login('plain')
        self.assertTrue(response.location.endswith('/dashboard'))

    def test_new_device_needs_code_then_is_trusted(self):
        secret = self.enable(1, time.time() - 120)
        response = self.login()
        self.assertTrue(response.location.endswith('/login/verify'))
        with self.client.session_transaction() as s:
            self.assertNotIn('admin_id', s)
            self.assertEqual(s['pending_2fa']['manager_id'], 1)
        self.assertEqual(self.client.post('/login/verify', data={'code': '000000' if self.code(secret) != '000000' else '111111'}).status_code, 401)
        response = self.client.post('/login/verify', data={'code': self.code(secret), 'trust': 'on'})
        self.assertTrue(response.location.endswith('/dashboard'))
        cookie = self.client.get_cookie(tfa.DEVICE_COOKIE)
        self.assertIsNotNone(cookie)
        with self.client.session_transaction() as s:
            self.assertEqual(s['admin_id'], 1)
            self.assertNotIn('pending_2fa', s)
        self.client.get('/login')
        with self.client.session_transaction() as s:
            s.clear()
        response = self.login()
        self.assertTrue(response.location.endswith('/dashboard'), 'trusted device skips the code')
        self.assertIn('LOGIN_2FA_SUCCESS', self.audit)

    def test_untrusted_choice_and_attempt_limit(self):
        secret = self.enable(1, time.time() - 120)
        self.login()
        self.client.post('/login/verify', data={'code': self.code(secret)})
        self.assertIsNone(self.client.get_cookie(tfa.DEVICE_COOKIE), 'no trust without the checkbox')
        with self.client.session_transaction() as s:
            s.clear()
        self.login()
        wrong = '000000' if self.code(secret) != '000000' else '111111'
        for _ in range(tfa.MAX_ATTEMPTS - 1):
            self.assertEqual(self.client.post('/login/verify', data={'code': wrong}).status_code, 401)
        response = self.client.post('/login/verify', data={'code': wrong})
        self.assertTrue(response.location.endswith('/login'))
        response = self.client.post('/login/verify', data={'code': self.code(secret, 30)})
        self.assertTrue(response.location.endswith('/login'), 'pending login is gone')

    def test_pending_expires(self):
        self.enable(1, time.time() - 120)
        self.login()
        with self.client.session_transaction() as s:
            pending = s['pending_2fa']
            pending['at'] = time.time() - tfa.PENDING_SECONDS - 1
            s['pending_2fa'] = pending
        self.assertTrue(self.client.get('/login/verify').location.endswith('/login'))


class WiringTests(unittest.TestCase):
    def test_public_paths_policy_and_templates(self):
        app = (ROOT / 'web/__init__.py').read_text(encoding='utf-8')
        self.assertIn("'login_verify'", app)
        self.assertEqual(app.count("'/login/verify'"), 2)
        policy = (ROOT / 'web/endpoint_permissions.py').read_text(encoding='utf-8')
        self.assertIn("'reset_manager_2fa_action': ['managers.manage']", policy)
        from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader
        env = Environment(loader=ChoiceLoader([DictLoader({'base.html': '{% block content %}{% endblock %}'}),
                                               FileSystemLoader(str(ROOT / 'web/templates'))]), autoescape=True)
        env.globals.update(url_for=lambda e, **k: '/' + e)
        html = env.get_template('profile_security.html').render(enabled=False, setup_secret='ABC', setup_uri='otpauth://x',
                                                                devices=[], trust_days=90)
        self.assertIn('data-uri="otpauth://x"', html)
        html = env.get_template('profile_security.html').render(enabled=True, setup_secret='', setup_uri='',
                                                                devices=[dict(label='<b>', created_at='a', last_seen_at='b', expires_at='c')], trust_days=90)
        self.assertIn('&lt;b&gt;', html)
        env.parse((ROOT / 'web/templates/login_verify.html').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
