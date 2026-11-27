"""User Manager import never invents a 10M/5M speed.

Imported packages are created without a speed (execute_userman_import writes
'0'/'0'; see DOMAIN_SPEED_20261125.md). The preview used to show 10M / 5M for
profiles without a router limitation because the parsers and both preview
tables filled that default. Profiles without a rate now carry an empty value,
and the preview states that the package is created without a speed.

Isolated: the parser functions are compiled from the module source with a fake
RouterOS client; no application import, database or router.
"""
import ast
import datetime
import re
import time
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPORTER = ROOT / 'services/mikrotik_userman_importer.py'
WANTED = {'fetch_userman_via_api', 'parse_rsc_content', 'parse_mikrotik_rate_limit', 'parse_mikrotik_bytes_to_mb',
          'parse_mikrotik_uptime_to_mins', 'parse_mikrotik_uptime_seconds', 'parse_mikrotik_validity',
          'parse_shared_users', 'extract_quota_from_name', 'clean_group_name'}


def load_parsers():
    tree = ast.parse(IMPORTER.read_text(encoding='utf-8'))
    ns = {'datetime': datetime, 're': re, 'time': time,
          'present_value': lambda p, k, d=None: p[k] if p.get(k) is not None else d,
          '_license_guarded': lambda *keys: lambda fn: fn}
    module = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in WANTED], type_ignores=[])
    exec(compile(module, 'importer', 'exec'), ns)
    return ns


class FakeRouter:
    """User Manager v6 with three profiles: no limitation, limitation without rate, limitation with rate."""

    def __init__(self, **kw):
        self.sock = types.SimpleNamespace(settimeout=lambda value: None)
        self.replies = iter([['!re', '=username=fixture1', '=actual-profile=NoLimit'], ['!done']])

    def connect(self):
        pass

    def login(self, **kw):
        return True

    def close(self):
        pass

    def talk_raw(self, words):
        return [('!done', {'ret': '1'})]

    def execute_command(self, path, words=None):
        if path == '/tool/user-manager/profile/print':
            return [{'name': 'NoLimit', 'validity': '1d'}, {'name': 'QuotaOnly', 'validity': '1d'},
                    {'name': 'WithRate', 'validity': '1d'}]
        if path == '/tool/user-manager/profile/limitation/print':
            return [{'name': 'L-quota', 'transfer-limit': '100M'},
                    {'name': 'L-rate', 'transfer-limit': '100M', 'rate-limit-rx': '2M', 'rate-limit-tx': '1M'}]
        return [{'profile': 'QuotaOnly', 'limitation': 'L-quota'}, {'profile': 'WithRate', 'limitation': 'L-rate'}]

    def write_sentence(self, words):
        pass

    def read_sentence(self):
        return next(self.replies)


RSC = """/tool user-manager profile
add name=NoLimit name-for-users=NoLimit validity=1d
add name=QuotaOnly name-for-users=QuotaOnly validity=1d
/tool user-manager profile limitation
add name=L-quota transfer-limit=100M
/tool user-manager profile profile-limitation
add limitation=L-quota profile=QuotaOnly
/tool user-manager user
add username=fixture1 password=fixture1 actual-profile=NoLimit
"""


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_parsers()

    def test_api_preview_has_no_invented_speed(self):
        self.ns['BufferedRouterOSApiProtocol'] = FakeRouter
        data = self.ns['fetch_userman_via_api']('192.0.2.1', 'fixture', 'fixture')
        speeds = {p['name']: (p['rate_down'], p['rate_up']) for p in data['profiles']}
        self.assertEqual(speeds['NoLimit'], ('', ''))
        self.assertEqual(speeds['QuotaOnly'], ('', ''))
        self.assertTrue(all(speeds['WithRate']))   # a real router value stays as reference only

    def test_rsc_preview_has_no_invented_speed(self):
        data = self.ns['parse_rsc_content'](RSC)
        profiles = data['profiles']
        profiles = profiles.values() if isinstance(profiles, dict) else profiles
        for profile in profiles:
            self.assertEqual((profile['rate_down'], profile['rate_up']), ('', ''), profile['name'])


class SourceTests(unittest.TestCase):
    def test_import_writes_no_speed_and_previews_say_so(self):
        importer = IMPORTER.read_text(encoding='utf-8')
        self.assertIn("p_down = '0'", importer)
        self.assertIn("p_up = '0'", importer)
        self.assertNotIn('"10M"', importer)
        self.assertNotIn("'10M'", importer)
        for name in ('web/templates/tools/unified_import.html', 'web/templates/tools/mikrotik_userman_import.html'):
            page = (ROOT / name).read_text(encoding='utf-8')
            self.assertNotIn("p.rate_down || '10M'", page, name)
            self.assertIn('>بدون سرعة</td>', page, name)


if __name__ == '__main__':
    unittest.main()
