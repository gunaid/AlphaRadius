"""Isolated checks for batch serials, bulk username checks, PDF grouping,
batch form defaults, data cost, RouterOS uptime parsing and the shared card
sheet macro. No application import, database server, router or browser."""
import ast
import datetime
import sqlite3
import sys
import unittest
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load(path, names, namespace=None):
    """Load selected top-level definitions without importing the module."""
    tree = ast.parse((ROOT / path).read_text(encoding='utf-8'))
    body = [node for node in tree.body
            if (isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names)
            or (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets))]
    namespace = {} if namespace is None else namespace
    exec(compile(ast.Module(body=body, type_ignores=[]), path, 'exec'), namespace)
    return namespace


class BatchSerialTests(unittest.TestCase):
    ns = load('services/voucher_service.py', {'batch_card_serial', 'SERIAL_SEQUENCE_DIGITS', 'MAX_BATCH_CARDS',
                                              '_taken_usernames'})

    def test_serial_is_batch_number_and_sequence_from_one(self):
        serial = self.ns['batch_card_serial']
        self.assertEqual(serial(78, 1), '7800001')
        self.assertEqual(serial(78, 10000), '7810000')
        self.assertEqual(self.ns['MAX_BATCH_CARDS'], 10000)

    def test_serials_never_collide_across_batches(self):
        serial = self.ns['batch_card_serial']
        seen = set()
        for batch in (1, 10, 11, 100, 101):
            for seq in range(1, 1201):
                value = serial(batch, seq)
                self.assertNotIn(value, seen)
                seen.add(value)

    def test_bulk_username_check_is_case_insensitive(self):
        db = sqlite3.connect(':memory:')
        db.row_factory = sqlite3.Row
        db.execute('CREATE TABLE wisp_vouchers(username TEXT)')
        db.execute('CREATE TABLE wisp_subscribers(username TEXT)')
        db.execute("INSERT INTO wisp_vouchers VALUES ('ABC123')")
        db.execute("INSERT INTO wisp_subscribers VALUES ('home7')")
        query = lambda sql, args: [dict(r) for r in db.execute(sql, args)]
        names = ['abc123', 'HOME7', 'free1'] + [f'n{i}' for i in range(1200)]
        self.assertEqual(self.ns['_taken_usernames'](query, names, True), {'abc123', 'home7'})


class PdfGroupingTests(unittest.TestCase):
    ns = load('services/batch_export_service.py', {'iter_card_pdf_groups'})

    def test_default_bound_is_unchanged(self):
        groups = list(self.ns['iter_card_pdf_groups'](list(range(400)), 40))
        self.assertEqual([len(sub) for sub, _ in groups], [120, 120, 120, 40])

    def test_lean_pages_carry_more_sheets_in_order(self):
        cards = list(range(1, 10001))
        groups = list(self.ns['iter_card_pdf_groups'](cards, 40, max_cards=500))
        self.assertEqual(len(groups), 21)
        flattened = [card for sub, pages in groups for page in pages for card in page]
        self.assertEqual(flattened, cards)
        self.assertTrue(all(len(page) <= 40 for _, pages in groups for page in pages))

    def test_invalid_bounds_are_rejected(self):
        with self.assertRaises(ValueError):
            list(self.ns['iter_card_pdf_groups']([1], 40, max_cards=0))


class FormDefaultsTests(unittest.TestCase):
    def setUp(self):
        self.ns = load('services/batch_form_defaults.py', {'FIELDS', 'DEFAULTS', '_int', '_flag', 'normalize'},
                       {'MAX_BATCH_CARDS': 10000, 'DEFAULT_SALE_POINT': 'توزيع عام'})

    def test_round_trip_keeps_booleans_and_bounds(self):
        normalize = self.ns['normalize']
        form = {'count': '300', 'format_type': 'pin_only', 'char_type': 'alphanumeric', 'same_user_pass': '1',
                'code_length': '10', 'pass_length': '6', 'reseller_id': '7', 'sale_point': ' كشك ', 'auto_pdf': '1'}
        stored = normalize(form)
        again = normalize(stored)
        self.assertEqual(stored, again)
        self.assertTrue(again['auto_pdf'] and again['same_user_pass'])
        self.assertEqual(again['sale_point'], 'كشك')
        self.assertEqual(normalize({'count': '20000'})['count'], 50)
        self.assertEqual(normalize({})['sale_point'], 'توزيع عام')


class DataCostTests(unittest.TestCase):
    def test_cost_from_bytes(self):
        ns = load('services/data_cost_service.py', {'GB', 'cost_for_bytes', 'format_cost'}, {'Decimal': Decimal})
        ns['gb_cost'] = lambda: Decimal('2.5')
        self.assertEqual(ns['cost_for_bytes'](3 * 1024 ** 3), Decimal('7.50'))
        self.assertEqual(ns['format_cost'](1024 ** 3, 'ر.ي'), '2.50 ر.ي')
        self.assertIsNone(ns['cost_for_bytes'](None))
        ns['gb_cost'] = lambda: Decimal('0')
        self.assertEqual(ns['format_cost'](1024 ** 3), '')

    def test_settings_parser(self):
        from services.system_settings_service import parse_gb_cost, setting_values
        self.assertEqual(parse_gb_cost('2.50'), '2.5')
        self.assertEqual(parse_gb_cost(''), '0')
        with self.assertRaises(ValueError):
            parse_gb_cost('-1')
        values = setting_values({'radius_msg_quota': '  transfer   limit reached ', 'gb_cost': '1'})
        self.assertEqual(values['radius_msg_quota'], 'transfer limit reached')
        self.assertNotIn('radius_msg_uptime', values)


class RouterUptimeTests(unittest.TestCase):
    def test_routeros_formats(self):
        ns = load('core/mikrotik_api.py', {'uptime_hours'})
        hours = ns['uptime_hours']
        self.assertEqual(hours('1w2d03:04:05'), 219)
        self.assertEqual(hours('3d4h5m6s'), 76)
        self.assertEqual(hours('05:10:00'), 5)
        self.assertIsNone(hours('-'))


class CardSheetMacroTests(unittest.TestCase):
    def test_sheet_renders_each_card_and_escapes_values(self):
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        env = Environment(loader=FileSystemLoader(str(ROOT / 'web/templates')), autoescape=select_autoescape(['html']))
        macro = env.get_template('components/card_sheet.html').module.card_sheet
        element = lambda **k: dict(enabled=True, x=50, y=50, **k)
        design = dict(cards_per_row=2, cards_per_col=5, cut_lines=1, border_color='#94a3b8', background_color='#fff',
                      bg_image='', design_type='clean', margin_top_mm=10, margin_page_mm=10, card_spacing_mm=0,
                      config={'elements': {'username': element(), 'serial': element(prefix='S/N: '),
                                           'qr_code': element(size=55)}})
        cards = [dict(id=i, username=f'<u{i}>', serial_number=f'1{i:05d}', login_url=f'http://w/l?u={i}')
                 for i in range(1, 4)]
        html = str(macro(cards, design))
        self.assertEqual(html.count('class="custom-card-cell"'), 3)
        self.assertIn('&lt;u1&gt;', html)
        self.assertNotIn('<u1>', html)
        self.assertIn('S/N: 100003', html)
        self.assertEqual(html.count('data-qr="http://w/l?u='), 3)


class RadiusMessageTests(unittest.TestCase):
    def test_reject_texts_come_from_fn_rmsg(self):
        from database.radius_message_schema import FUNCTION_SQL, DEFAULTS
        queries = (ROOT / 'docker/freeradius/queries.conf').read_text(encoding='utf-8')
        postauth = (ROOT / 'docker/freeradius/license-capacity-postauth.conf').read_text(encoding='utf-8')
        for kind in ('quota', 'uptime', 'expired', 'recharged', 'disabled', 'invalid', 'reconcile'):
            self.assertIn(f"fn_rmsg('{kind}')COLLATE utf8mb4_unicode_ci", queries)
        for kind in ('mac', 'capacity', 'simultaneous', 'license'):
            self.assertIn(f"SELECT fn_rmsg('{kind}')", postauth)
        self.assertNotIn('لقد استهلكت', queries)
        for kind, text in DEFAULTS:
            self.assertIn(f"WHEN '{kind}' THEN '{text}'", FUNCTION_SQL)
        self.assertIn("CONCAT('radius_msg_',p_kind)", FUNCTION_SQL)


class PrintRouteContractTests(unittest.TestCase):
    def test_limits_and_lean_template(self):
        source = (ROOT / 'web/routes/vouchers.py').read_text(encoding='utf-8')
        self.assertNotIn('1 إلى 2000 كرت', source)
        self.assertIn("render_template('print_cards_pdf.html'", source)
        self.assertIn('resolve_card_design(batch.get(\'package_id\'))', source)
        pdf = (ROOT / 'web/templates/print_cards_pdf.html').read_text(encoding='utf-8')
        self.assertNotIn('tailwind', pdf)
        self.assertNotIn('fontawesome', pdf)


if __name__ == '__main__':
    unittest.main()
