"""Cloned MACs: router profile copies (RouterOS 6/7 shapes), cookies, detection
inputs, RADIUS wiring and routes. Isolated: no app import, DB server or router.
The SQL function and detection query run in tests/run_roaming_mariadb_lab.py."""
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services import cloned_mac_service as cloned  # noqa: E402


# Shapes as printed by the API: v6 uses advertise-interval and yes/no-like
# booleans as "true"/"false"; v7 adds fields such as mac-cookie-timeout.
V6_DEFAULT = {'.id': '*0', 'name': 'default', 'idle-timeout': 'none', 'keepalive-timeout': '2m',
              'status-autorefresh': '1m', 'shared-users': '1', 'add-mac-cookie': 'true',
              'mac-cookie-timeout': '3d', 'address-list': '', 'transparent-proxy': 'false',
              'open-status-page': 'always', 'advertise': 'false', 'advertise-interval': '30m,10m',
              'on-login': ':log info "in"', 'default': 'true'}
V7_PACKAGE = {'.id': '*2', 'name': 'pkg-2M', 'idle-timeout': 'none', 'keepalive-timeout': '2m',
              'shared-users': '1', 'add-mac-cookie': 'true', 'mac-cookie-timeout': '3d',
              'rate-limit': '2M/2M', 'on-login': '/ip firewall address-list add list=x address=$address',
              'insert-queue-before': 'first', 'parent-queue': 'none', 'queue-type': 'default-small',
              'open-status-page': 'always', 'transparent-proxy': 'true', 'advertise': 'false'}


class FakeRouter:
    """Minimal /ip/hotspot RouterOS API: profiles and cookies, optional traps."""

    def __init__(self, profiles, cookies=(), refuse=()):
        self.profiles = [dict(p) for p in profiles]
        self.cookies = [dict(c) for c in cookies]
        self.refuse = set(refuse)      # field names that make add/set trap
        self.calls = []

    def talk_raw(self, words):
        self.calls.append(words)
        command, args = words[0], dict(w[1:].split('=', 1) for w in words[1:] if w.startswith('='))
        if command.endswith('/print'):
            rows = self.profiles if 'profile' in command else self.cookies
            return [('!re', dict(r)) for r in rows] + [('!done', {})]
        if any(field in self.refuse for field in args):
            return [('!trap', {'message': 'unknown parameter'}), ('!done', {})]
        if command == '/ip/hotspot/user/profile/add':
            args['add-mac-cookie'] = 'false' if args.get('add-mac-cookie') == 'no' else 'true'
            self.profiles.append(dict(args, **{'.id': f'*{len(self.profiles) + 10}'}))
        elif command == '/ip/hotspot/user/profile/set':
            ident = args.pop('.id')
            row = next(p for p in self.profiles if p['.id'] == ident)
            args['add-mac-cookie'] = 'false' if args.get('add-mac-cookie') == 'no' else row['add-mac-cookie']
            row.update(args)
        elif command == '/ip/hotspot/cookie/remove':
            self.cookies = [c for c in self.cookies if c['.id'] != args['.id']]
        return [('!done', {})]

    def profile(self, name):
        return next((p for p in self.profiles if p['name'] == name), None)


class ProfileCopyTests(unittest.TestCase):
    def test_copies_present_fields_only_and_disables_cookie(self):
        words = cloned.profile_words(V6_DEFAULT, 'default-nocookie')
        self.assertEqual(words[0], '=name=default-nocookie')
        self.assertEqual(words[-1], '=add-mac-cookie=no')
        self.assertIn('=on-login=:log info "in"', words)
        self.assertIn('=advertise-interval=30m,10m', words)
        self.assertFalse(any(w.startswith(('=.id=', '=default=', '=rate-limit=')) for w in words))

    def test_sync_creates_a_copy_per_profile_on_both_versions(self):
        router = FakeRouter([V6_DEFAULT, V7_PACKAGE])
        verified, failed = cloned.sync_profiles(router)
        self.assertEqual((sorted(verified), failed), (['default-nocookie', 'pkg-2M-nocookie'], []))
        copy = router.profile('pkg-2M-nocookie')
        self.assertEqual((copy['add-mac-cookie'], copy['rate-limit'], copy['on-login'], copy['queue-type']),
                         ('false', '2M/2M', V7_PACKAGE['on-login'], 'default-small'))
        self.assertEqual(router.profile('pkg-2M')['add-mac-cookie'], 'true', 'the original is untouched')

    def test_second_sync_updates_instead_of_duplicating(self):
        router = FakeRouter([V7_PACKAGE])
        cloned.sync_profiles(router)
        router.profile('pkg-2M')['rate-limit'] = '4M/4M'
        verified, _ = cloned.sync_profiles(router)
        self.assertEqual(verified, ['pkg-2M-nocookie'])
        self.assertEqual([p['name'] for p in router.profiles].count('pkg-2M-nocookie'), 1)
        self.assertEqual(router.profile('pkg-2M-nocookie')['rate-limit'], '4M/4M')

    def test_refused_field_falls_back_to_minimal_copy(self):
        router = FakeRouter([V7_PACKAGE], refuse={'queue-type'})
        verified, failed = cloned.sync_profiles(router)
        self.assertEqual((verified, failed), (['pkg-2M-nocookie'], []))
        copy = router.profile('pkg-2M-nocookie')
        self.assertEqual((copy['add-mac-cookie'], copy['on-login']), ('false', V7_PACKAGE['on-login']))
        self.assertNotIn('queue-type', copy)

    def test_copy_that_cannot_be_made_is_never_recorded(self):
        router = FakeRouter([V7_PACKAGE], refuse={'name'})
        self.assertEqual(cloned.sync_profiles(router), ([], ['pkg-2M-nocookie']))

    def test_copy_left_with_cookie_on_is_not_trusted(self):
        manual = dict(V7_PACKAGE, **{'.id': '*9', 'name': 'pkg-2M-nocookie'})
        router = FakeRouter([V7_PACKAGE, manual], refuse={'add-mac-cookie'})
        verified, failed = cloned.sync_profiles(router)
        self.assertEqual((verified, failed), ([], ['pkg-2M-nocookie']))

    def test_existing_cookies_of_listed_macs_are_removed(self):
        router = FakeRouter([], cookies=[{'.id': '*1', 'mac-address': 'AA:AA:AA:AA:AA:01', 'user': 'x'},
                                         {'.id': '*2', 'mac-address': 'BB:BB:BB:BB:BB:02', 'user': 'y'}])
        self.assertEqual(cloned.remove_cookies(router, ['aa:aa:aa:aa:aa:01']), 1)
        self.assertEqual([c['.id'] for c in router.cookies], ['*2'])
        self.assertEqual(cloned.remove_cookies(router, []), 0)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.db = types.ModuleType('database.db')
        self.db.query_one = Mock(return_value=None)
        self.db.query_all = Mock(return_value=[])
        self.db.execute_write = Mock()
        self.db.execute_update = Mock(return_value=1)
        self.modules = patch.dict(sys.modules, {'database.db': self.db})
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def test_add_normalizes_and_rejects_bad_input(self):
        mac, new = cloned.add_mac(' aa-bb-cc-dd-ee-ff ', '  shared   phones ', 'admin', 'detected')
        self.assertEqual((mac, new), ('AA:BB:CC:DD:EE:FF', True))
        self.assertEqual(self.db.execute_write.call_args.args[1], ('AA:BB:CC:DD:EE:FF', 'shared phones', 'detected', 'admin'))
        self.db.query_one.return_value = {'mac': mac}
        self.assertEqual(cloned.add_mac(mac), (mac, False))
        with self.assertRaises(ValueError):
            cloned.add_mac('not-a-mac')

    def test_detection_params_are_bounded(self):
        p = cloned.detection_params({'days': '500', 'min_cards': '1', 'min_ports': 'x', 'min_short': '7'})
        self.assertEqual((p['days'], p['min_cards'], p['min_ports'], p['min_short']), (90, 2, 2, 7))

    def test_router_without_api_is_reported_not_contacted(self):
        result = cloned.sync_router({'name': 'r1', 'ip_address': '10.0.0.1', 'api_port': None, 'api_username': ''}, [])
        self.assertEqual((result['ok'], result['error']), (False, 'لا توجد بيانات API'))

    def test_sync_records_only_verified_copies(self):
        router = FakeRouter([V7_PACKAGE])
        router.connect, router.close, router.login = Mock(), Mock(), Mock(return_value=True)
        api = types.ModuleType('core.mikrotik_api')
        api.RouterOSApiProtocol = Mock(return_value=router)
        with patch.dict(sys.modules, {'core.mikrotik_api': api}):
            result = cloned.sync_router({'name': 'r1', 'ip_address': '10.0.0.1', 'api_port': 8728,
                                         'api_username': 'api', 'api_password': 'x'}, [])
        self.assertTrue(result['ok'])
        stored = [c.args[1] for c in self.db.execute_write.call_args_list]
        self.assertEqual(stored, [('10.0.0.1', 'pkg-2M-nocookie')])
        self.assertIn('DELETE FROM wisp_cloned_mac_profiles', self.db.execute_update.call_args.args[0])
        router.close.assert_called_once()

    def test_periodic_sync_is_rate_limited_and_needs_list(self):
        cloned._last_sync = cloned._last_check = 0.0
        with patch.object(cloned, 'enabled', return_value=True), \
                patch.object(cloned, 'list_macs', return_value=[{'mac': 'AA:AA:AA:AA:AA:01'}]), \
                patch.object(cloned, 'sync_all', return_value=['done']) as sync:
            self.assertEqual(cloned.maybe_sync(now=1000), ['done'])
            cloned._last_sync = 1000
            self.assertIsNone(cloned.maybe_sync(now=1030))     # checked less than a minute ago
            self.assertIsNone(cloned.maybe_sync(now=1500))     # synced less than 15 minutes ago
            self.assertEqual(cloned.maybe_sync(now=2000), ['done'])
        self.assertEqual(sync.call_count, 2)
        with patch.object(cloned, 'enabled', return_value=False), patch.object(cloned, 'sync_all') as sync:
            cloned._last_check = 0.0
            self.assertIsNone(cloned.maybe_sync(now=9000))
        sync.assert_not_called()


class WiringTests(unittest.TestCase):
    def test_postauth_switches_hotspot_profile_only(self):
        postauth = (ROOT / 'docker/freeradius/license-capacity-postauth.conf').read_text(encoding='utf-8')
        block = postauth[postauth.index('Cloned MACs'):]
        self.assertIn('if (!&Framed-Protocol || (&Framed-Protocol != "PPP"))', block)
        self.assertIn("fn_cloned_mac_profile('%{Calling-Station-Id}', '%{NAS-IP-Address}', '%{reply:Mikrotik-Group}')", block)
        self.assertIn('Mikrotik-Group := "%{control:Tmp-String-5}"', block)
        # Placed after the capacity decision and rate refresh, so it never decides access.
        self.assertGreater(postauth.index('Cloned MACs'), postauth.index('Mikrotik-Rate-Limit := "%{control:Tmp-String-3}"'))

    def test_function_requires_feature_list_and_confirmed_copy(self):
        from database.cloned_mac_schema import FUNCTION_SQL, PROFILE_SUFFIX
        for part in ("`key`='cloned_mac_enabled'", 'FROM wisp_cloned_macs', 'FROM wisp_cloned_mac_profiles',
                     "p.nasipaddress=p_nasip", f"'{PROFILE_SUFFIX}'", "COALESCE(NULLIF(p_group,''),'default')"):
            self.assertIn(part, FUNCTION_SQL)

    def test_listed_macs_are_excluded_from_roaming(self):
        from database.license_capacity import RESERVE_SQL
        gate = RESERVE_SQL[RESERVE_SQL.index('account_slots>=account_cap THEN'):RESERVE_SQL.index('SET roaming_seat=1')]
        self.assertIn('FROM wisp_cloned_macs', gate)
        source = (ROOT / 'database/license_capacity.py').read_text(encoding='utf-8')
        body = source[source.index('def install_capacity_schema'):]
        self.assertLess(body.index('install_cloned_mac_schema(cur)'), body.index('ensure_schema_object(cur, definition)'))

    def test_routes_permissions_and_image(self):
        from core.permission_catalog import required_detail
        policy = (ROOT / 'web/endpoint_permissions.py').read_text(encoding='utf-8')
        routes = (ROOT / 'web/routes/nas.py').read_text(encoding='utf-8')
        for endpoint, permission in (('cloned_macs_page', 'nas.view'), ('cloned_macs_add', 'nas.manage'),
                                     ('cloned_macs_delete', 'nas.manage'), ('cloned_macs_settings', 'nas.manage'),
                                     ('cloned_macs_sync', 'nas.manage')):
            self.assertIn(f"'{endpoint}': ['{permission}']", policy)
            self.assertIn(f'endpoint="{endpoint}"', routes)
            self.assertTrue(required_detail(endpoint))
        self.assertIn('database/cloned_mac_schema.py', (ROOT / 'Dockerfile').read_text(encoding='utf-8'))

    def test_page_template_parses(self):
        from jinja2 import Environment, FileSystemLoader
        Environment(loader=FileSystemLoader(str(ROOT / 'web/templates'))).parse(
            (ROOT / 'web/templates/cloned_macs.html').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
