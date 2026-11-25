"""Explicit synthetic MariaDB lab for the comprehensive report; no application, NAS or HTTP.

Needs a disposable database named report_fixture that already has the full
application schema (tables, owned views and triggers, e.g. copied with
``mariadb-dump --no-data --routines --triggers`` from a local test install):

    DB_SOCKET=... DB_USER=... DB_PASSWORD=... DB_NAME=report_fixture \\
        python tests/run_comprehensive_report_lab.py --run

It refuses any other database, deletes and reseeds only the rows it uses, and
runs services.comprehensive_report_service.report() against the real SQL,
including network_traffic_service.sessions_sql(with_seconds=True).
"""
import datetime as dt
import os
import sys
import types
import unittest
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DB = 'report_fixture'
NOW = dt.datetime(2026, 11, 25, 9, 0, tzinfo=dt.timezone.utc)
SEEDED = ('wisp_voucher_sales', 'wisp_sale_sources', 'wisp_vouchers', 'wisp_voucher_batches', 'wisp_packages',
          'wisp_managers', 'radacct', 'radacct_archive', 'wisp_account_usage_summary', 'wisp_account_usage_seals',
          'wisp_traffic_history', 'wisp_session_service_evidence', 'wisp_nas_devices', 'wisp_invoices')
GIB = 1024 ** 3


def connect():
    import pymysql
    options = dict(user=os.environ['DB_USER'], password=os.environ.get('DB_PASSWORD', ''), database=FIXTURE_DB,
                   charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor, autocommit=False)
    if os.environ.get('DB_SOCKET'):
        options['unix_socket'] = os.environ['DB_SOCKET']
    else:
        options['host'] = os.environ['DB_HOST']
    return pymysql.connect(**options)


def seed(cur):
    from services.sales_source_service import server_key
    cur.execute('SELECT DATABASE() AS name')
    assert cur.fetchone()['name'] == FIXTURE_DB
    cur.execute('SET FOREIGN_KEY_CHECKS=0')
    for table in SEEDED:
        cur.execute('DELETE FROM ' + table)
    cur.execute("INSERT INTO wisp_nas_devices(id,name,ip_address,secret) VALUES (1,'برج الشمال','10.0.0.1','x')")
    cur.execute("INSERT INTO wisp_managers(id,username,full_name,password_hash,role_id) VALUES (7,'res7','موزع سبعة','x',3)")
    cur.execute("""INSERT INTO wisp_packages(id,name,price,cost,rate_download,rate_upload,service_type,is_active)
                   VALUES (1,'باقة 1GB',100,80,'0','0','hotspot',1),(2,'باقة 5GB',300,250,'0','0','hotspot',1)""")
    cur.execute("""INSERT INTO wisp_voucher_batches(id,name,batch_number,package_id,card_count,price,reseller_id,sale_point)
                   VALUES (1,'b1','1',1,2,100,7,'كشك الحارة'),(2,'b2','2',2,1,300,NULL,'')""")
    cur.execute("""INSERT INTO wisp_vouchers(id,batch_id,package_id,reseller_id,serial_number,username,password,pin_code,status)
                   VALUES (1,1,1,7,'100001','card1','p','card1','active'),(2,2,2,NULL,'200001','card2','p','card2','active'),
                          (3,1,1,7,'100002','card3','p','card3','unused')""")
    sales = [(1, 1, 1, 1, 'card1', 'باقة 1GB', 100, 80, 7, '2026-11-10 09:30:00'),
             (2, 2, 2, 2, 'card2', 'باقة 5GB', 300, 250, None, '2026-11-10 20:15:00'),
             (3, 1, None, 1, 'card1', 'باقة 1GB', 100, 80, 7, '2026-11-12 09:10:00'),
             (4, 3, 3, 1, 'card3', 'باقة 1GB', 100, 80, 7, '2026-10-01 12:00:00')]
    for sid, vid, first, batch, user, pkg, price, cost, reseller, at in sales:
        cur.execute("""INSERT INTO wisp_voucher_sales(id,voucher_id,first_activation_voucher_id,batch_id,batch_name,username,
            package_name,price,cost,reseller_id,activated_at,created_at) VALUES (%s,%s,%s,%s,'b',%s,%s,%s,%s,%s,%s,%s)""",
                    (sid, vid, first, batch, user, pkg, price, cost, reseller, at, at))
    for sid, name in ((1, 'hs-vlan10'), (2, 'hs-vlan20')):
        cur.execute("""INSERT INTO wisp_sale_sources(event_kind,event_id,server_key,nas_address,nas_label,service_type,server_name)
                       VALUES ('voucher',%s,%s,'10.0.0.1','برج الشمال','hotspot',%s)""",
                    (sid, server_key('10.0.0.1', 'hotspot', name, ''), name))
    sessions = [('u1', 'card1', 'hs-vlan10', '2026-11-10 10:00:00', '2026-11-10 11:00:00', 3600, 100 * 2 ** 20, GIB),
                ('u2', 'card2', 'hs-vlan20', '2026-11-10 21:00:00', '2026-11-10 23:00:00', 7200, 50 * 2 ** 20, 2 * GIB),
                ('u3', 'card1', 'hs-vlan10', '2026-11-12 09:20:00', None, 600, 2 ** 20, 10 * 2 ** 20),
                ('u4', 'card1', 'hs-vlan10', '2026-10-02 09:20:00', '2026-10-02 10:20:00', 3600, GIB, GIB)]
    for uid, user, server, start, stop, seconds, up, down in sessions:
        cur.execute("""INSERT INTO radacct(acctsessionid,acctuniqueid,username,nasipaddress,nasportid,
            acctstarttime,acctupdatetime,acctstoptime,acctsessiontime,acctinputoctets,acctoutputoctets,calledstationid,
            callingstationid,servicetype,framedprotocol,acctterminatecause,framedipaddress)
            VALUES (%s,%s,%s,'10.0.0.1','vlan',%s,%s,%s,%s,%s,%s,%s,'AA:AA:AA:AA:AA:01','Login-User','','','10.5.0.2')""",
                    (uid, (uid * 16)[:32], user, start, stop or start, stop, seconds, up, down, server))
    cur.execute("""INSERT INTO wisp_invoices(invoice_number,subscriber_name,amount,status,package_name,paid_at)
                   VALUES ('INV1','sub',50,'paid','home','2026-11-11 10:00:00')""")
    cur.execute('SET FOREIGN_KEY_CHECKS=1')


class ComprehensiveReportLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = connect()
        with cls.conn.cursor() as cur:
            seed(cur)
        cls.conn.commit()
        import pymysql
        db = types.ModuleType('database.db')
        db.get_connection = lambda: connect()

        def query_one(sql, args=()):
            with cls.conn.cursor() as cur:
                cur.execute(sql.replace('?', '%s'), args)
                return cur.fetchone()
        db.query_one = query_one
        db.query_all = lambda sql, args=(): []
        clock = types.ModuleType('core.time_service')
        clock.get_configured_timezone_name = lambda: 'Asia/Aden'
        cls.modules = patch.dict(sys.modules, {'database.db': db, 'core.time_service': clock})
        cls.modules.start()
        from services import data_cost_service
        data_cost_service.clear_cache()

    @classmethod
    def tearDownClass(cls):
        cls.modules.stop()
        cls.conn.close()

    def report(self, owner=None, **args):
        from services import comprehensive_report_service as report
        with patch('core.ownership.owner_id', return_value=owner), \
                patch.object(report, 'measured_total', return_value=None), \
                patch('services.data_cost_service.gb_cost', return_value=Decimal('2')):
            return report.report(dict(dict(period='custom', date_from='2026-11-01', date_to='2026-11-30'), **args),
                                 now=NOW, timezone='Asia/Aden')

    def test_sales_by_first_login_package_sale_point_reseller(self):
        data = self.report()
        k = data['kpi']
        self.assertEqual((k['sold'], k['renewals']), (2, 1))
        self.assertEqual((k['revenue'], k['cost'], k['profit']), (Decimal('500.00'), Decimal('410.00'), Decimal('90.00')))
        packages = {r['name']: (r['sold'], r['renewals'], r['revenue']) for r in data['sales']['packages']}
        self.assertEqual(packages, {'باقة 1GB': (1, 1, Decimal('200.00')), 'باقة 5GB': (1, 0, Decimal('300.00'))})
        points = {r['name']: r['revenue'] for r in data['sales']['sale_points']}
        self.assertEqual(points, {'كشك الحارة': Decimal('200.00'), 'توزيع عام': Decimal('300.00')})
        resellers = {r['name']: r['revenue'] for r in data['sales']['resellers']}
        self.assertEqual(resellers, {'موزع سبعة': Decimal('200.00'), 'بيع مباشر': Decimal('300.00')})
        self.assertEqual(k['best_package']['name'], 'باقة 5GB')
        self.assertEqual(k['best_sale_point']['name'], 'توزيع عام')
        self.assertEqual([(d['day'], d['revenue']) for d in data['sales']['days']],
                         [('2026-11-10', Decimal('400.00')), ('2026-11-12', Decimal('100.00'))])
        self.assertEqual(k['peak_hour'], 9)
        self.assertEqual(k['invoices'], {'count': 1, 'amount': Decimal('50.00')})

    def test_consumption_hours_points_and_packages(self):
        data = self.report()
        k = data['kpi']
        total = 100 * 2 ** 20 + GIB + 50 * 2 ** 20 + 2 * GIB + 2 ** 20 + 10 * 2 ** 20
        self.assertEqual(k['bytes'], total)
        self.assertEqual(k['hours'], round((3600 + 7200 + 600) / 3600, 1))
        self.assertEqual((k['users'], k['sessions']), (2, 3))
        self.assertEqual(k['data_cost'], (Decimal(total) / GIB * 2).quantize(Decimal('0.01')))
        by_server = {p['server_label']: p for p in data['points']}
        vlan20 = next(p for label, p in by_server.items() if 'hs-vlan20' in label)
        vlan10 = next(p for label, p in by_server.items() if 'hs-vlan10' in label)
        self.assertEqual((vlan20['hours'], vlan20['sold'], vlan20['revenue']), (2.0, 1, Decimal('300.00')))
        self.assertEqual((vlan10['sessions'], vlan10['sold'], vlan10['nas_label']), (2, 1, 'برج الشمال'))
        self.assertEqual(data['points'][0]['server_key'], vlan20['server_key'], 'ranked by consumption')
        usage = {r['name']: r['total'] for r in data['usage']['packages']}
        self.assertEqual(usage['باقة 5GB'], 50 * 2 ** 20 + 2 * GIB)
        self.assertEqual(data['usage']['top_users'][0]['username'], 'card2')

    def test_reseller_sees_only_own_rows(self):
        data = self.report(owner=7)
        k = data['kpi']
        self.assertEqual((k['sold'], k['renewals'], k['revenue']), (1, 1, Decimal('200.00')))
        self.assertEqual(data['sales']['resellers'], [])
        self.assertIsNone(k['invoices'])
        self.assertEqual(k['users'], 1)
        self.assertEqual({u['username'] for u in data['usage']['top_users']}, {'card1'})

    def test_period_and_export(self):
        data = self.report(period='custom', date_from='2026-10-01', date_to='2026-10-31')
        self.assertEqual((data['kpi']['sold'], data['kpi']['hours']), (1, 1.0))
        from services.comprehensive_report_service import workbook
        import openpyxl
        book = openpyxl.load_workbook(workbook(self.report()))
        self.assertIn('الباقات - المبيعات', book.sheetnames)
        self.assertIn('السيرفرات والمنافذ', book.sheetnames)
        summary = {row[0].value: row[1].value for row in book['الملخص'].iter_rows()}
        self.assertEqual(summary['كروت مباعة (أول دخول)'], 2)

    def test_page_renders_with_real_data(self):
        from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader
        from services.network_traffic_service import format_bytes
        env = Environment(loader=ChoiceLoader([DictLoader({'base.html': '{% block content %}{% endblock %}'}),
                                               FileSystemLoader(str(ROOT / 'web/templates'))]), autoescape=True)
        env.globals.update(url_for=lambda endpoint, **kw: '/' + endpoint, can_access_endpoint=lambda e: True)
        for owner in (None, 7):
            html = env.get_template('comprehensive_report.html').render(traffic_bytes=format_bytes,
                                                                         **self.report(owner=owner))
            self.assertIn('باقة 1GB', html)
            self.assertIn('hs-vlan10', html)
            self.assertEqual('موزع سبعة' in html, owner is None)


def main():
    if sys.argv[1:] != ['--run'] or os.environ.get('DB_NAME') != FIXTURE_DB:
        raise SystemExit(f'Requires --run and the dedicated {FIXTURE_DB} database')
    sys.path.insert(0, str(ROOT))
    result = unittest.main(argv=[sys.argv[0], '-v'], exit=False).result
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
