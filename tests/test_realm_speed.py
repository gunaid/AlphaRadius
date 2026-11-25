"""Hotspot domain choices (card@512k/2M|yes) and empty package speeds.

Isolated: no application import, database server, router or FreeRADIUS.
fn_realm_policy/fn_record_realm_choice run in tests/run_roaming_mariadb_lab.py;
the FreeRADIUS policy was run end to end locally (see the feature doc).
"""
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SAMPLE_SITE = """authorize {
\t#  See policy.d/filter for the definition of the filter_username policy.
\t#
\tfilter_username
\tpreprocess
\t-sql
}
preacct {
\tpreprocess
\tacct_unique
}
"""


class EntrypointTests(unittest.TestCase):
    def test_policy_runs_before_filter_username_and_acct_unique(self):
        script = (ROOT / 'docker/freeradius/entrypoint.sh').read_text(encoding='utf-8')
        block = script[script.index("if ! grep -q 'ALPHA_REALM_EXTRACT'"):]
        block = block[:block.index('\nfi\n') + 4]
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            site = Path(folder) / 'sites-available'
            site.mkdir()
            (site / 'default').write_text(SAMPLE_SITE)
            for _ in range(2):   # idempotent on container restart
                subprocess.run(['bash', '-c', block], env={'CONF_DIR': folder, 'PATH': '/usr/bin:/bin'}, check=True)
            text = (site / 'default').read_text()
        lines = [line.strip() for line in text.splitlines()]
        self.assertEqual(lines.count('alpha_realm_extract'), 1)
        self.assertEqual(lines.count('alpha_realm_username'), 1)
        self.assertLess(lines.index('alpha_realm_extract'), lines.index('filter_username'))
        self.assertEqual(lines[lines.index('preacct {') + 2], 'alpha_realm_username')
        self.assertIn('\talpha_realm_username', text.splitlines())   # a real tab, not a literal "t"

    def test_policy_and_postauth_wiring(self):
        policy = (ROOT / 'docker/freeradius/alpha-realm-policy.conf').read_text(encoding='utf-8')
        self.assertIn('alpha_realm_extract {', policy)
        self.assertIn('alpha_realm_username {', policy)
        self.assertEqual(policy.count("fn_realm_policy('%{control:Tmp-String-8}')"), 3)
        # Only a valid domain (non-empty policy) rewrites User-Name.
        self.assertEqual(policy.count('&User-Name := "%{control:Tmp-String-7}"'), 2)
        postauth = (ROOT / 'docker/freeradius/license-capacity-postauth.conf').read_text(encoding='utf-8')
        block = postauth[postauth.index('Hotspot domain choices'):postauth.index('Cloned MACs')]
        self.assertIn('(!&reply:Mikrotik-Rate-Limit || (&reply:Mikrotik-Rate-Limit == "0/0"))', block)
        self.assertIn('!&reply:Mikrotik-Address-List', block)
        self.assertIn('fn_record_realm_choice(', block)
        self.assertGreater(postauth.index('Hotspot domain choices'),
                           postauth.index('Mikrotik-Rate-Limit := "%{control:Tmp-String-3}"'))
        docker = (ROOT / 'docker/freeradius/Dockerfile').read_text(encoding='utf-8')
        self.assertIn('COPY alpha-realm-policy.conf /etc/freeradius/3.0/policy.d/alpha-realm-policy', docker)
        self.assertIn('database/realm_policy_schema.py', (ROOT / 'Dockerfile').read_text(encoding='utf-8'))

    def test_schema_installed_with_capacity_objects(self):
        source = (ROOT / 'database/license_capacity.py').read_text(encoding='utf-8')
        self.assertIn('install_realm_policy_schema(cur)', source)
        from database.realm_policy_schema import POLICY_SQL, RECORD_SQL
        self.assertIn("'=7C','|'", POLICY_SQL)
        self.assertIn("'=3B',';'", RECORD_SQL)
        self.assertIn("`key`='realm_speed_enabled'", POLICY_SQL)


class PackageSpeedTests(unittest.TestCase):
    def form(self, **values):
        base = dict(name='p', price='1', cost='0', validity_unit='days', validity_value='30', service_type='hotspot')
        base.update(values)
        return base

    def test_empty_speed_is_open(self):
        from services.package_validation import validate_package_form
        values = validate_package_form(self.form())
        self.assertEqual((values['rate_download'], values['rate_upload']), ('0', '0'))
        values = validate_package_form(self.form(rate_download='', rate_upload=''))
        self.assertEqual((values['rate_download'], values['rate_upload']), ('0', '0'))
        self.assertEqual(validate_package_form(self.form(rate_download='4M', rate_upload='2M'))['rate_download'], '4M')
        with self.assertRaises(ValueError):
            validate_package_form(self.form(rate_download='fast', rate_upload='2M'))
        with self.assertRaises(ValueError):
            validate_package_form(self.form(rate_download='', rate_upload='2M'))

    def test_defaults_in_forms_routes_and_import(self):
        add = (ROOT / 'web/templates/package_add.html').read_text(encoding='utf-8')
        self.assertIn('name="rate_download" value=""', add)
        self.assertIn('name="rate_upload" value=""', add)
        self.assertNotIn('value="4M" required', add)
        routes = (ROOT / 'web/routes/packages.py').read_text(encoding='utf-8')
        self.assertNotIn("'rate_download', '2M'", routes)
        importer = (ROOT / 'services/mikrotik_userman_importer.py').read_text(encoding='utf-8')
        self.assertIn("p_down = '0'", importer)
        self.assertNotIn("prof.get('rate_down', '10M')", importer)


class PageTests(unittest.TestCase):
    def test_settings_validation_and_script(self):
        from services import realm_speed_service as realm
        db = types.ModuleType('database.db')
        db.query_one = Mock(return_value=None)
        db.execute_write = Mock()
        db.execute_update = Mock()
        with patch.dict(sys.modules, {'database.db': db}):
            self.assertEqual(realm.save_settings({'enabled': 'on', 'block_list': 'no-updates'}),
                             {'enabled': True, 'block_list': 'no-updates'})
            self.assertEqual(realm.save_settings({}), {'enabled': False, 'block_list': 'block-updates'})
            with self.assertRaises(ValueError):
                realm.save_settings({'block_list': 'bad name;'})
        script = realm.router_script('no-updates')
        self.assertIn('src-address-list=no-updates', script)
        self.assertIn('tls-host="play.googleapis.com"', script)
        self.assertIn('remove [find where comment~"ALPHA block updates"]', script)
        self.assertIn('src-address-list=block-updates', realm.router_script('x y'))

    def test_page_renders(self):
        from jinja2 import Environment, FileSystemLoader, ChoiceLoader, DictLoader, StrictUndefined
        env = Environment(loader=ChoiceLoader([DictLoader({'base.html': '{% block content %}{% endblock %}'}),
                                               FileSystemLoader(str(ROOT / 'web/templates'))]),
                          undefined=StrictUndefined, autoescape=True)
        env.globals.update(url_for=lambda endpoint, **kw: '/' + endpoint, can_access_endpoint=lambda e: True)
        html = env.get_template('realm_speed.html').render(
            settings={'enabled': True, 'block_list': 'block-updates'}, script='/ip firewall filter <x>',
            choices=[dict(username='6875843', realm='512k/2M|yes', rate='512k/2M', block_updates=1,
                          nasipaddress='10.0.0.1', callingstationid='AA:AA:AA:AA:AA:01', updated_at='now')])
        self.assertIn('6875843', html)
        self.assertIn('&lt;x&gt;', html)

    def test_routes_and_permissions(self):
        from core.permission_catalog import required_detail
        policy = (ROOT / 'web/endpoint_permissions.py').read_text(encoding='utf-8')
        for endpoint, permission in (('realm_speed_page', 'nas.view'), ('realm_speed_settings', 'nas.manage')):
            self.assertIn(f"'{endpoint}': ['{permission}']", policy)
            self.assertTrue(required_detail(endpoint))


if __name__ == '__main__':
    unittest.main()
