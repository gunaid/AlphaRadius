"""User Manager 6 used cards ('restart' mode) and package group import.

Isolated parts. The full import, Core's authorize_check_query and the undo are
exercised against MariaDB by tests/run_userman_used_cards_lab.py.
"""
import ast
import datetime
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.import_state_service import restarted_used_state, source_usage  # noqa: E402

MB = 1048576
NOW = datetime.datetime(2026, 11, 27, 9, 30, 15, 123456)
PLAN = dict(validity_value=2, validity_unit='days', volume_quota_mb=300, uptime_limit_mins=420)


def load(name):
    path = ROOT / 'services/mikrotik_userman_importer.py'
    node = next(n for n in ast.parse(path.read_text(encoding='utf-8')).body if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), ns)
    return ns[name]


class RestartedStateTests(unittest.TestCase):
    def row(self, **kw):
        base = dict(uptime_used_mins=325, uptime_used_seconds=19526, download_used_bytes=219415946, upload_used_bytes=27337694)
        base.update(kw)
        return base

    def test_remaining_balance_and_validity_from_import(self):
        state = restarted_used_state(self.row(), PLAN, NOW)
        start = NOW.replace(microsecond=0)
        self.assertEqual(state['status'], 'active')
        self.assertEqual((state['first_used_at'], state['last_renewed_at']), (start, start))
        self.assertEqual(state['expires_at'], start + datetime.timedelta(days=2))
        self.assertEqual((state['upload_bytes'], state['download_bytes'], state['uptime_seconds']), (27337694, 219415946, 19526))
        self.assertTrue(state['history'])

    def test_each_limit_checked_on_its_own(self):
        self.assertEqual(restarted_used_state(self.row(download_used_bytes=300 * MB, upload_used_bytes=0), PLAN, NOW)['status'], 'expired')
        self.assertEqual(restarted_used_state(self.row(uptime_used_seconds=7 * 3600), PLAN, NOW)['status'], 'expired')
        self.assertEqual(restarted_used_state(self.row(uptime_used_seconds=7 * 3600 - 1), PLAN, NOW)['status'], 'active')
        unlimited = dict(PLAN, volume_quota_mb=0, uptime_limit_mins=0)
        self.assertEqual(restarted_used_state(self.row(download_used_bytes=10 ** 12), unlimited, NOW)['status'], 'active')
        self.assertEqual(restarted_used_state(self.row(disabled=True), PLAN, NOW)['status'], 'disabled')

    def test_validity_units_and_no_validity(self):
        start = NOW.replace(microsecond=0)
        self.assertEqual(restarted_used_state(self.row(), dict(PLAN, validity_value=7, validity_unit='hours'), NOW)['expires_at'],
                         start + datetime.timedelta(hours=7))
        self.assertIsNone(restarted_used_state(self.row(), dict(PLAN, validity_value=0), NOW)['expires_at'])

    def test_usage_sources(self):
        self.assertEqual(source_usage({'uptime_used_mins': 3}), (0, 0, 180), 'minutes when seconds are absent')
        self.assertEqual(source_usage({'uptime_used_seconds': 0, 'uptime_used_mins': 3}), (0, 0, 0))
        self.assertEqual(source_usage({'upload_used_mb': 1, 'download_used_mb': 2}), (MB, 2 * MB, 0))
        with self.assertRaises(ValueError):
            source_usage({'upload_used_bytes': -1})


class GroupNameTests(unittest.TestCase):
    def test_clean_group_name(self):
        clean = load('clean_group_name')
        self.assertEqual(clean('hs-100'), 'hs-100')
        self.assertEqual(clean(' "Profile 1" '), 'Profile 1')
        for bad in (None, '', 'none', 'NONE', 'a;b', 'a"b', "a'b", 'x\ny', 'g' * 101):
            self.assertEqual(clean(bad), '', bad)


class MaskedPasswordTests(unittest.TestCase):
    def test_routeros_masked_password_is_not_a_password(self):
        ns = {'re': re}
        path = ROOT / 'services/mikrotik_userman_importer.py'
        node = next(n for n in ast.parse(path.read_text(encoding='utf-8')).body
                    if isinstance(n, ast.FunctionDef) and n.name == 'source_password')
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), ns)
        source_password = ns['source_password']
        self.assertEqual(source_password('*****', '35528211572'), ('35528211572', True))
        self.assertEqual(source_password('*', 'c1'), ('c1', True))
        self.assertEqual(source_password('', 'c1'), ('c1', False))
        self.assertEqual(source_password(None, 'c1'), ('c1', False))
        self.assertEqual(source_password('  ', 'c1'), ('c1', False))
        self.assertEqual(source_password('pa*ss', 'c1'), ('pa*ss', False), 'real passwords are kept')
        self.assertEqual(source_password('1234', 'c1'), ('1234', False))


class WiringTests(unittest.TestCase):
    def test_importer(self):
        text = (ROOT / 'services/mikrotik_userman_importer.py').read_text(encoding='utf-8')
        self.assertIn("used_cards_mode='review'):", text)
        self.assertIn("if used_cards_mode not in ('review', 'restart'):", text)
        self.assertIn("restart_used = used_cards_mode == 'restart' and has_usage", text)
        self.assertIn("'group_name': clean_group_name(attrs.get('group-name'))", text)
        self.assertIn("'group_name': clean_group_name(lim.get('group-name'))", text)
        self.assertIn('simultaneous_sessions, mikrotik_group, is_active, created_at', text)
        self.assertNotIn("?, 'ALL-SPEED'", text, 'card group follows its package')
        self.assertNotIn("'User Manager - '+package_names[pid]", text, 'one batch naming')
        self.assertIn('INSERT INTO wisp_session_baselines', text)
        self.assertIn("upass, masked = source_password(u.get('password'), uname)", text)
        self.assertNotIn("u.get('password', uname).strip() or uname", text)
        journal = (ROOT / 'services/userman_import_journal.py').read_text(encoding='utf-8')
        self.assertIn("DELETE FROM wisp_session_baselines WHERE radacctid=%s AND renewed_at=%s", journal)

    def test_route_job_and_pages(self):
        nas = (ROOT / 'web/routes/nas.py').read_text(encoding='utf-8')
        self.assertIn("used_cards_mode=used_cards_mode", nas)
        job = (ROOT / 'services/userman_job_service.py').read_text(encoding='utf-8')
        self.assertIn("('used_cards_mode','review')", job)
        self.assertIn("options['used_cards_mode'] not in ('review','restart')", job)
        for page in ('mikrotik_userman_import.html', 'unified_import.html'):
            html = (ROOT / 'web/templates/tools' / page).read_text(encoding='utf-8')
            self.assertIn('<option value="restart">', html, page)
            self.assertRegex(html, r"used_cards_mode: ?usedCardsMode", page)
            self.assertIn('st.restarted_used_users', html, page)
            self.assertIn('st.masked_passwords', html, page)
        progress = (ROOT / 'web/static/userman-progress.js').read_text(encoding='utf-8')
        self.assertEqual(progress.count("restarted_used_users"), 2)
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(str(ROOT / 'web/templates')))
        for page in ('tools/mikrotik_userman_import.html', 'tools/unified_import.html'):
            env.parse((ROOT / 'web/templates' / page).read_text(encoding='utf-8'))


class BatchExportMessageTests(unittest.TestCase):
    def test_server_reason_is_shown_not_hidden_as_connection_loss(self):
        html = (ROOT / 'web/templates/vouchers.html').read_text(encoding='utf-8')
        body = html[html.index('async function downloadBatchFile'):html.index('function handlePrintBtnClick')]
        self.assertIn('failure.fromServer = true;', body)
        self.assertIn("if (error && error.fromServer) operationSwal.fire('تعذر التصدير', error.message, 'error');", body)
        self.assertIn('else operationSwal.uncertain();', body)
        self.assertNotIn("operationSwal.uncertain('تعذر التصدير', error.message", body)


if __name__ == '__main__':
    unittest.main()
