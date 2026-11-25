"""Sale points and card-provider exports (PDF boxes only, Excel one card per row).

Isolated: SQLite stand-in for database.db; the PDF is rendered with the real
Chromium renderer (needs Chromium like the other PDF suites) and read back.
"""
import io
import sqlite3
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services import provider_export_service as provider  # noqa: E402
from services import sale_point_service as points  # noqa: E402


class Db(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
            CREATE TABLE wisp_system_settings(`key` TEXT PRIMARY KEY, `value` TEXT, description TEXT);
            CREATE TABLE wisp_voucher_batches(id INTEGER PRIMARY KEY, name TEXT, reseller_id INT, sale_point TEXT);
            CREATE TABLE wisp_vouchers(id INTEGER PRIMARY KEY, batch_id INT, username TEXT, password TEXT,
                                       status TEXT, reseller_id INT, serial_number TEXT);
            INSERT INTO wisp_voucher_batches VALUES (1,'b1',NULL,'كشك'),(2,'b2',7,'');
            INSERT INTO wisp_vouchers VALUES
              (1,1,'0012345','0012345','unused',NULL,'100002'),
              (2,1,'0099999','0099999','active',NULL,'100001'),
              (3,1,'0000001','0000001','unused',NULL,'100001'),
              (4,2,'user7','pass7','unused',7,'200001');''')
        module = types.ModuleType('database.db')

        def run(sql, args=()):
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur
        module.get_connection = lambda: types.SimpleNamespace(cursor=self.db.cursor, rollback=self.db.rollback, close=lambda: None)
        module.is_mysql_conn = lambda conn: False
        module.adapt_query = lambda sql, conn=None: sql
        module.query_one = lambda sql, args=(): (dict(r) if (r := run(sql, args).fetchone()) else None)
        module.query_all = lambda sql, args=(): [dict(r) for r in run(sql, args).fetchall()]
        module.execute_write = lambda sql, args=(): run(sql, args).lastrowid
        module.execute_update = lambda sql, args=(): run(sql, args).rowcount
        self.modules = patch.dict(sys.modules, {'database.db': module})
        self.modules.start()
        self.addCleanup(self.modules.stop)


class CardValueTests(unittest.TestCase):
    def test_code_and_optional_password(self):
        self.assertEqual(provider.card_values({'username': '0012', 'password': '0012'}), ['0012'])
        self.assertEqual(provider.card_values({'username': '0012', 'password': ''}), ['0012'])
        self.assertEqual(provider.card_values({'username': 'u', 'password': 'p'}), ['u', 'p'])
        for bad in ({'username': ''}, {'username': 'a\nb'}, {'username': 'a', 'password': 'b\rc'}, {'username': 5}):
            with self.assertRaises(ValueError):
                provider.card_values(bad)


class ExportTests(Db):
    def test_only_unused_cards_in_serial_order(self):
        batch, values, skipped = provider.provider_cards(1)
        self.assertEqual(batch['name'], 'b1')
        self.assertEqual(values, [['0000001'], ['0012345']])
        self.assertEqual(skipped, 1)
        self.assertEqual(provider.provider_cards(2, owner=7)[1], [['user7', 'pass7']])
        with self.assertRaises(LookupError):
            provider.provider_cards(2, owner=8)
        with self.assertRaises(LookupError):
            provider.provider_cards(99)

    def test_excel_has_only_cards_as_text(self):
        import openpyxl
        sheet = openpyxl.load_workbook(provider.workbook([['0000001'], ['0012345'], ['u', 'p']])).active
        rows = [[c.value for c in row if c.value is not None] for row in sheet.iter_rows()]
        self.assertEqual(rows, [['0000001'], ['0012345'], ['u', 'p']])
        self.assertTrue(all(cell.data_type == 's' for row in sheet.iter_rows() for cell in row if cell.value))

    def test_pdf_html_has_boxes_only(self):
        values = [[f'{i:07d}'] for i in range(1, provider.PAGE_BOXES + 3)] + [['<u>', 'p&w']]
        parts = list(provider.pdf_pages(values))
        self.assertEqual(len(parts), 1)
        html = parts[0]
        self.assertEqual(html.count('class="page"'), 2)
        self.assertEqual(html.count('<div class="box'), len(values))
        self.assertIn('&lt;u&gt;<br>p&amp;w', html)
        self.assertNotIn('<u>', html)
        self.assertEqual(len(list(provider.pdf_pages([['1']] * (provider.PAGE_BOXES * 20 + 1)))), 2)

    def test_real_pdf_contains_only_the_codes(self):
        from pypdf import PdfReader
        from services.pdf_export_service import render_parts
        values = [[f'{i:07d}'] for i in range(1, 51)]
        with render_parts(provider.pdf_pages(values), str(ROOT / 'web/static'), timeout=180) as payload:
            reader = PdfReader(io.BytesIO(payload.read()))
        self.assertEqual(len(reader.pages), 2)
        text = ''.join(page.extract_text() for page in reader.pages)
        self.assertEqual(sorted(text.split()), [v[0] for v in values])

    def test_download_name(self):
        with patch('services.batch_export_service.batch_export_name', return_value='باقة-12-50-2026.pdf'):
            self.assertEqual(provider.download_name(12, 'pdf', 'x'), 'باقة-12-50-2026-مزود.pdf')


class SalePointTests(Db):
    def test_seed_once_add_rename_toggle(self):
        points.ensure_table()
        names = [p['name'] for p in points.list_points()]
        self.assertEqual(sorted(names), sorted(['توزيع عام', 'كروت الشبكة (tabweeb)']))
        self.db.execute("DELETE FROM wisp_sale_points WHERE kind='provider'")
        points.ensure_table()
        self.assertEqual(len(points.list_points()), 1, 'a deleted seed is not re-added')
        points.save_point({'name': '  كشك  ', 'kind': 'shop'})
        with self.assertRaises(ValueError):
            points.save_point({'name': 'كشك'})
        with self.assertRaises(ValueError):
            points.save_point({'name': '   '})
        point = next(p for p in points.list_points() if p['name'] == 'كشك')
        points.save_point({'name': 'كشك الحارة', 'kind': 'wallet', 'note': 'n'}, point['id'])
        self.assertEqual(self.db.execute('SELECT sale_point FROM wisp_voucher_batches WHERE id=1').fetchone()[0], 'كشك الحارة')
        points.toggle_point(point['id'])
        self.assertNotIn('كشك الحارة', [p['name'] for p in points.list_points(active_only=True)])
        self.assertEqual(points.batch_counts()['كشك الحارة']['unused'], 2)
        self.assertEqual(points.batch_counts()['توزيع عام']['cards'], 1)


class WiringTests(unittest.TestCase):
    def test_routes_permissions_and_templates(self):
        policy = (ROOT / 'web/endpoint_permissions.py').read_text(encoding='utf-8')
        for endpoint, permission in (('export_batch_provider_pdf', 'vouchers.print'), ('export_batch_provider_excel', 'vouchers.print'),
                                     ('sale_points_page', 'vouchers.view'), ('sale_point_save', 'vouchers.actions')):
            self.assertIn(f"'{endpoint}': ['{permission}']", policy)
        routes = (ROOT / 'web/routes/vouchers.py').read_text(encoding='utf-8')
        guard = routes[routes.index('def guard_voucher_permissions'):routes.index("permission = 'vouchers.print'")]
        self.assertIn("'export_batch_provider_pdf','export_batch_provider_excel'", guard)
        self.assertEqual(routes.count('if owner_id() is not None:\n        return jsonify(success=False, message=\'نقاط البيع يديرها مدير الشبكة.\'), 403'), 2)
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(str(ROOT / 'web/templates')))
        for name in ('sale_points.html', 'vouchers.html'):
            env.parse((ROOT / 'web/templates' / name).read_text(encoding='utf-8'))
        vouchers = (ROOT / 'web/templates/vouchers.html').read_text(encoding='utf-8')
        self.assertIn("/provider.pdf", vouchers)
        self.assertIn('list="salePointOptions"', vouchers)


if __name__ == '__main__':
    unittest.main()
