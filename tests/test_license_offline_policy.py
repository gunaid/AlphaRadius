"""License offline policy: signed grace/RADIUS windows, staged lock, fallback
servers, offline renewal tokens, stage alerts and the watchdog exception.

Isolated: no application import, database, network or license server. Guard
functions are loaded from source with explicit stubs (same pattern as the
other license suites); signatures use throwaway Ed25519 keys.
"""
import ast
import base64
import datetime
import json
import logging
import os
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import licensing  # noqa: E402

GUARD = ROOT / 'services' / 'license_guard_service.py'
HOUR = 3600


def pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def sign(key, payload):
    data = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return {'payload': payload, 'signature': base64.b64encode(key.sign(data)).decode()}


def load(names, namespace):
    tree = ast.parse(GUARD.read_text(encoding='utf-8'))
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(GUARD), 'exec'), namespace)
    return namespace


class Keys(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        trust = ((licensing.AMAN_LICENSE_AUTHORITY, pem(self.key)),)
        patcher = patch.multiple(licensing, TRUSTED_LICENSE_PUBLIC_KEYS=trust,
                                 get_master_public_key_pem=lambda authority=None: pem(self.key),
                                 get_machine_id=lambda: 'HW-1', get_instance_uuid=lambda: 'INST-1')
        patcher.start()
        self.addCleanup(patcher.stop)

    def license_payload(self, **extra):
        payload = dict(license_id='LIC-1', client_name='c', hardware_id='ANY', instance_id='ANY',
                       is_lifetime=False, expires_at='2099-01-01T00:00:00Z', limits={'max_active_sessions': 10})
        payload.update(extra)
        return payload


class PolicyTests(Keys):
    def test_defaults_and_bounds(self):
        self.assertEqual(licensing.offline_policy({}), {'grace_hours': 48, 'radius_hours': 24})
        self.assertEqual(licensing.offline_policy({'offline_policy': {'grace_hours': 168, 'radius_hours': 0}}),
                         {'grace_hours': 168, 'radius_hours': 0})
        for bad in ({'grace_hours': 0}, {'grace_hours': 169}, {'grace_hours': 48.0}, {'grace_hours': True},
                    {'radius_hours': 73}, {'radius_hours': '24'}, 'x'):
            with self.assertRaises(ValueError, msg=bad):
                licensing.offline_policy({'offline_policy': bad})

    def test_fallback_urls(self):
        self.assertEqual(licensing.heartbeat_urls({'heartbeat_urls': ['https://ls2.example.com/']}),
                         ['https://ls2.example.com'])
        for bad in (['http://ls2.example.com'], ['https://u:p@x.com'], ['https://x.com?a=1'], ['a'] * 4, 'https://x.com', [1]):
            with self.assertRaises(ValueError, msg=bad):
                licensing.heartbeat_urls({'heartbeat_urls': bad})

    def test_signed_package_carries_policy_and_rejects_bad_values(self):
        good = sign(self.key, self.license_payload(offline_policy={'grace_hours': 72, 'radius_hours': 12},
                                                   heartbeat_urls=['https://ls2.example.com']))
        ok, _, info = licensing.verify_license_package(good)
        self.assertTrue(ok)
        self.assertEqual((info['grace_hours'], info['radius_hours'], info['heartbeat_urls']),
                         (72, 12, ['https://ls2.example.com']))
        plain_ok, _, plain = licensing.verify_license_package(sign(self.key, self.license_payload()))
        self.assertEqual((plain_ok, plain['grace_hours'], plain['radius_hours']), (True, 48, 24))
        bad_ok, message, _ = licensing.verify_license_package(sign(self.key, self.license_payload(offline_policy={'grace_hours': 500})))
        self.assertFalse(bad_ok)
        self.assertIn('168', message)

    def test_stage_boundaries(self):
        stage = licensing.offline_stage
        self.assertEqual(stage(0, 48, 24), ('ok', 48))
        self.assertEqual(stage(HOUR, 48, 24)[0], 'ok')
        self.assertEqual(stage(HOUR + 1, 48, 24), ('grace', 47))
        self.assertEqual(stage(48 * HOUR, 48, 24), ('grace', 1))
        self.assertEqual(stage(48 * HOUR + 1, 48, 24), ('admin_locked', 24))
        self.assertEqual(stage(72 * HOUR, 48, 24), ('admin_locked', 1))
        self.assertEqual(stage(72 * HOUR + 1, 48, 24), ('locked', 0))
        self.assertEqual(stage(2 * HOUR + 1, 2, 0), ('locked', 0), 'radius_hours 0 locks at once')


class OfflineRenewalTests(Keys):
    def token(self, **changes):
        now = int(time.time())
        payload = dict(type='offline_renewal', license_id='LIC-1', hardware_id='HW-1', instance_id='ANY',
                       issued_at=now - 60, valid_until=now + 7 * 86400, nonce='ab' * 16)
        payload.update(changes)
        return sign(self.key, payload)

    def verify(self, token, **license_changes):
        return licensing.verify_offline_renewal(token, self.license_payload(**license_changes))

    def test_valid_token(self):
        ok, _, data = self.verify(self.token())
        self.assertTrue(ok)
        self.assertEqual(data['nonce'], 'ab' * 16)

    def test_rejections(self):
        now = int(time.time())
        cases = {
            'type': self.token(type='license'),
            'license': self.token(license_id='LIC-2'),
            'hardware': self.token(hardware_id='HW-OTHER'),
            'instance': self.token(instance_id='INST-OTHER'),
            'expired': self.token(valid_until=now - 1),
            'too long': self.token(issued_at=now, valid_until=now + 31 * 86400),
            'future issue': self.token(issued_at=now + 3600),
            'nonce': self.token(nonce='not-hex'),
            'float': self.token(valid_until=float(now + 3600)),
        }
        for name, token in cases.items():
            self.assertFalse(self.verify(token)[0], name)
        tampered = self.token()
        tampered['payload']['valid_until'] += 86400
        self.assertFalse(self.verify(tampered)[0], 'tampered payload')
        foreign = sign(Ed25519PrivateKey.generate(), self.token()['payload'])
        self.assertFalse(self.verify(foreign)[0], 'unknown signer')
        self.assertFalse(self.verify(self.token(), expires_at='2000-01-01T00:00:00Z')[0], 'past license expiry')
        self.assertTrue(self.verify(self.token(), is_lifetime=True, expires_at='')[0], 'lifetime has no expiry cap')

    def test_apply_is_single_use(self):
        stored = []
        row = {'license_id': 'LIC-1', 'raw_package_json': json.dumps({'payload': self.license_payload()})}

        def query_one(sql, args=()):
            if 'FROM wisp_license_info' in sql:
                return row
            return {'nonce': args[0]} if any(r[0] == args[0] for r in stored) else None
        ns = load({'apply_offline_renewal'}, dict(
            json=json, datetime=datetime, query_one=query_one, decode_license_string=licensing.decode_license_string,
            verify_offline_renewal=licensing.verify_offline_renewal, check_and_update_monotonic_time=lambda: (True, ''),
            execute_write=lambda sql, args: stored.append(args), clear_license_cache=lambda: None))
        token = json.dumps(self.token())
        ok, message = ns['apply_offline_renewal'](token, 'admin')
        self.assertTrue(ok, message)
        self.assertEqual((stored[0][0], stored[0][1], stored[0][4]), ('ab' * 16, 'LIC-1', 'admin'))
        self.assertEqual(ns['apply_offline_renewal'](base64.b64encode(token.encode()).decode())[0], False)
        self.assertEqual(len(stored), 1)
        ns['check_and_update_monotonic_time'] = lambda: (False, 'rollback')
        self.assertFalse(ns['apply_offline_renewal'](json.dumps(self.token(nonce='cd' * 16)))[0])


class StatusStageTests(unittest.TestCase):
    """get_active_license_status with stubs: stages follow the signed policy."""

    def status(self, hours_offline, info_extra=None, offline_until=None):
        last = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours_offline)
        row = dict(id=1, license_id='LIC-1', client_name='c', plan_tier='E', hardware_id='ANY', status='active',
                   expires_at='', raw_package_json='{"payload":{}}', last_verified_at=last, last_heartbeat_at=last,
                   master_server_url='https://ls.amtik.online')
        info = dict(license_authority=licensing.AMAN_LICENSE_AUTHORITY, requires_heartbeat=True, features={},
                    license_mode='active_sessions', max_active_sessions=0, max_nas=15, max_managers=10,
                    is_lifetime=True, days_left=9999, grace_hours=48, radius_hours=24)
        info.update(info_extra or {})
        ns = load({'get_active_license_status'}, {
            '_LICENSE_CACHE': {'data': None, 'timestamp': 0}, 'DEFAULT_MASTER_SERVER_URL': 'https://ls.amtik.online',
            'AMAN_LICENSE_AUTHORITY': licensing.AMAN_LICENSE_AUTHORITY, 'time': time, 'datetime': datetime,
            'json': json, 'logger': logging.getLogger('offline-test'), 'ensure_license_tables': lambda: None,
            'get_machine_id': lambda: 'HW', 'get_instance_uuid': lambda: 'INST', 'get_combined_binding_code': lambda: 'B',
            'get_current_system_counts': lambda: (1, 1, 1), 'check_and_update_monotonic_time': lambda: (True, ''),
            'query_one': lambda *_: row, 'verify_license_package': lambda *_a, **_k: (True, 'ok', info),
            'is_license_blacklisted': lambda *_: False, 'get_pending_reservations_count': lambda: 0,
            'get_consumed_license_seats': lambda: 1, 'GRACE_HOURS_DEFAULT': 48, 'RADIUS_HOURS_DEFAULT': 24,
            'offline_stage': licensing.offline_stage, 'offline_renewal_until': lambda *_: offline_until})
        return ns['get_active_license_status'](force_refresh=True)

    def test_stages(self):
        ok = self.status(0.5)
        self.assertEqual((ok['valid'], ok['radius_allowed'], ok['offline_stage']), (True, True, 'ok'))
        grace = self.status(30)
        self.assertEqual((grace['valid'], grace['grace_period'], grace['grace_hours_left']), (True, True, 18))
        admin = self.status(50)
        self.assertEqual((admin['valid'], admin['radius_allowed'], admin['status']), (False, True, 'grace_admin_locked'))
        self.assertEqual(admin['grace_hours_left'], 22)
        locked = self.status(80)
        self.assertEqual((locked['valid'], locked['radius_allowed'], locked['status']), (False, False, 'grace_expired'))

    def test_signed_policy_and_offline_renewal(self):
        self.assertEqual(self.status(50, {'grace_hours': 72})['offline_stage'], 'grace')
        self.assertEqual(self.status(3, {'grace_hours': 2, 'radius_hours': 0})['radius_allowed'], False)
        future = time.time() + 86400
        renewed = self.status(500, offline_until=future)
        self.assertEqual((renewed['valid'], renewed['offline_stage']), (True, 'ok'))
        self.assertTrue(renewed['offline_until'])
        # After a renewal expires, the windows count from its end, not the old heartbeat.
        lapsed = self.status(500, offline_until=time.time() - 30 * HOUR)
        self.assertEqual(lapsed['offline_stage'], 'grace')


class WiringTests(unittest.TestCase):
    def test_fallback_candidates(self):
        ns = load({'license_server_candidates'}, dict(os=os, DEFAULT_MASTER_SERVER_URL='https://ls.amtik.online',
                                                      signed_heartbeat_urls=licensing.heartbeat_urls))
        package = {'payload': {'heartbeat_urls': ['https://ls2.example.com', 'https://ls.amtik.online/']}}
        with patch.dict(os.environ, {'ALPHA_LICENSE_FALLBACK_URLS': 'http://insecure.example.com, https://ls3.example.com'}):
            self.assertEqual(ns['license_server_candidates']('https://ls.amtik.online/', package),
                             ['https://ls.amtik.online', 'https://ls2.example.com', 'https://ls3.example.com'])
        bad = {'payload': {'heartbeat_urls': 'nope'}}
        self.assertEqual(ns['license_server_candidates'](None, bad), ['https://ls.amtik.online'])

    def test_stage_alert_once_per_change(self):
        stored, alerts = {}, []
        watchdog = types.ModuleType('core.watchdog')
        watchdog.log_system_alert = lambda *a, **k: alerts.append((a, k))
        state = {'stage': 'grace'}
        ns = load({'record_offline_stage'}, dict(
            get_active_license_status=lambda force_refresh=False: {'offline_stage': state['stage'], 'grace_hours_left': 5},
            query_one=lambda *_: ({'value': stored['v']} if 'v' in stored else None),
            execute_write=lambda sql, args: stored.update(v=args[-1] if 'UPDATE' in sql else args[1]),
            OFFLINE_STAGE_ALERTS=None, logger=logging.getLogger('stage')))
        source = GUARD.read_text(encoding='utf-8')
        ns['OFFLINE_STAGE_ALERTS'] = eval(compile(ast.parse(source[source.index('OFFLINE_STAGE_ALERTS = ') + 23:
                                                                  source.index('\n\n\ndef record_offline_stage')],
                                                           mode='eval'), 'alerts', 'eval'))
        with patch.dict(sys.modules, {'core.watchdog': watchdog}):
            for stage in ('grace', 'grace', 'admin_locked', 'ok'):
                state['stage'] = stage
                ns['record_offline_stage']()
        self.assertEqual([a[0][0] for a in alerts],
                         ['LICENSE_OFFLINE_GRACE', 'LICENSE_OFFLINE_ADMIN_LOCKED', 'LICENSE_OFFLINE_RECOVERED'])
        self.assertIn('5', alerts[0][0][2])

    def test_watchdog_keeps_sessions_while_radius_allowed(self):
        source = (ROOT / 'core' / 'watchdog.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'enforce_license_compliance_hook')
        enqueue = Mock()
        guard = types.ModuleType('services.license_guard_service')
        coa = types.ModuleType('services.coa_queue_service')
        coa.enqueue_disconnect = enqueue
        ns = dict(query_all=lambda *_: [{'username': 'u', 'nasipaddress': '1.1.1.1'}], execute_update=lambda *_: 0,
                  log_system_alert=lambda *a, **k: None, datetime=datetime)
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'watchdog', 'exec'), ns)
        with patch.dict(sys.modules, {'services.license_guard_service': guard, 'services.coa_queue_service': coa}):
            guard.get_active_license_status = lambda: {'valid': False, 'radius_allowed': True, 'status': 'grace_admin_locked'}
            ns['enforce_license_compliance_hook']()
            enqueue.assert_not_called()
            guard.get_active_license_status = lambda: {'valid': False, 'radius_allowed': False, 'status': 'grace_expired'}
            ns['enforce_license_compliance_hook']()
            enqueue.assert_called()

    def test_routes_and_pages(self):
        app = (ROOT / 'web' / '__init__.py').read_text(encoding='utf-8')
        self.assertEqual(app.count("'/settings/license/offline-renewal'"), 2)
        policy = (ROOT / 'web' / 'endpoint_permissions.py').read_text(encoding='utf-8')
        self.assertIn("'offline_license_renewal_action': ['system.settings']", policy)
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(str(ROOT / 'web' / 'templates')))
        env.parse((ROOT / 'web' / 'templates' / 'license_status.html').read_text(encoding='utf-8'))
        self.assertIn('offline_license_renewal_action',
                      (ROOT / 'web' / 'templates' / 'license_status.html').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
