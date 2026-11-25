"""Comprehensive report: pure aggregation rules, wiring and the opt-in session time.

Isolated: no application import, database server or HTTP. The SQL runs in
tests/run_comprehensive_report_lab.py against a disposable MariaDB.
"""
import datetime as dt
import sys
import unittest
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services import comprehensive_report_service as report  # noqa: E402


def sale(**values):
    row = dict(sold=0, renewals=0, revenue=Decimal('0'), cost=Decimal('0'))
    row.update(values)
    return report._sales_numbers(row)


class TimeSeriesTests(unittest.TestCase):
    def test_storage_buckets_follow_the_configured_timezone(self):
        buckets = [sale(bucket='2026-11-10 23:00:00', sold=2, revenue=Decimal('20')),
                   sale(bucket=dt.datetime(2026, 11, 11, 1, 0), sold=1, renewals=1, revenue=Decimal('15'))]
        days, hours = report.time_series(buckets, 'Asia/Aden')
        self.assertEqual([(d['day'], d['sold']) for d in days], [('2026-11-10', 2), ('2026-11-11', 1)])
        days, hours = report.time_series(buckets, 'Africa/Cairo')    # UTC+2: one hour earlier
        self.assertEqual(hours[22]['sold'], 2)
        self.assertEqual(hours[0]['revenue'], Decimal('15'))
        self.assertEqual(len(hours), 24)


class CombineTests(unittest.TestCase):
    def test_points_merge_sales_into_consumption_by_server_key(self):
        usage = [report._usage_numbers(dict(server_key='a', nas_label='R1', server_label='hs1', service_type='hotspot',
                                            sessions=3, users=2, download=10, upload=5, seconds=7200))]
        sales = [sale(server_key='a', sold=2, revenue=Decimal('200')),
                 sale(server_key='b', nas_address='10.0.0.9', server_name='hs9', sold=1, revenue=Decimal('50'))]
        points = report.merge_points(usage, sales)
        self.assertEqual([(p['server_key'], p['total'], p['hours'], p['sold']) for p in points],
                         [('a', 15, 2.0, 2), ('b', 0, 0.0, 1)])
        self.assertEqual(points[1]['nas_label'], '10.0.0.9')

    def test_kpis_derive_profit_cost_net_and_best(self):
        sales = dict(summary=sale(sold=3, renewals=1, revenue=Decimal('400'), cost=Decimal('300')),
                     packages=[sale(name='A', revenue=Decimal('100')), sale(name='B', revenue=Decimal('300'))],
                     sale_points=[], resellers=[], days=[],
                     hours=[dict(hour=h, sold=5 if h == 20 else 1) for h in range(24)])
        usage = dict(totals=report._usage_numbers(dict(sessions=4, users=2, download=2 * report.GB, upload=0, seconds=36000)),
                     points=[], packages=[])
        k = report.kpis(sales, usage, Decimal('3'), dict(invoices=None, active_now=None, roaming={}, measured_bytes=None))
        self.assertEqual((k['profit'], k['data_cost'], k['net']), (Decimal('100'), Decimal('6.00'), Decimal('94.00')))
        self.assertEqual((k['avg_price'], k['hours'], k['hours_per_user']), (Decimal('100.00'), 10.0, 5.0))
        self.assertEqual(k['best_package']['name'], 'B')
        self.assertEqual(k['peak_hour'], 20)
        self.assertIsNone(k['best_sale_point'])
        no_cost = report.kpis(sales, usage, Decimal('0'), dict(invoices=None, active_now=None, roaming={}, measured_bytes=None))
        self.assertIsNone(no_cost['data_cost'])
        self.assertIsNone(no_cost['net'])

    def test_empty_period_has_no_best_and_no_division(self):
        sales = dict(summary=sale(), packages=[sale(name='A')], sale_points=[], resellers=[], days=[],
                     hours=[dict(hour=h, sold=0) for h in range(24)])
        usage = dict(totals=report._usage_numbers(dict(sessions=0, users=0, download=0, upload=0, seconds=0)),
                     points=[], packages=[])
        k = report.kpis(sales, usage, Decimal('1'), dict(invoices=None, active_now=None, roaming={}, measured_bytes=None))
        self.assertIsNone(k['best_package'])
        self.assertIsNone(k['peak_hour'])
        self.assertIsNone(k['avg_price'])
        self.assertIsNone(k['bytes_per_user'])

    def test_filters(self):
        selected, start, end = report.selected_filters({}, now=dt.datetime(2026, 11, 25, tzinfo=dt.timezone.utc))
        self.assertEqual(selected['period'], 'this_month')
        self.assertEqual(start, dt.datetime(2026, 11, 1))
        with self.assertRaises(ValueError):
            report.selected_filters({'period': 'forever'})


class WiringTests(unittest.TestCase):
    def test_session_time_is_opt_in(self):
        from services.network_traffic_service import sessions_sql
        default, _ = sessions_sql()
        timed, _ = sessions_sql(with_seconds=True)
        self.assertNotIn(' AS seconds', default)
        self.assertEqual(timed.count(' AS seconds'), 2)       # session rows and settled summaries
        self.assertIn("counter('acctsessiontime','uptime_seconds')",
                      (ROOT / 'services/network_traffic_service.py').read_text(encoding='utf-8'))

    def test_routes_permissions_feature_and_menu(self):
        from core.permission_catalog import required_detail
        policy = (ROOT / 'web/endpoint_permissions.py').read_text(encoding='utf-8')
        features = (ROOT / 'core/license_feature_policy.py').read_text(encoding='utf-8')
        for endpoint in ('comprehensive_report', 'comprehensive_report_export'):
            self.assertIn(f"'{endpoint}': ['invoices.view']", policy)
            self.assertTrue(required_detail(endpoint))
            self.assertIn(endpoint, features[features.index("'sales_reports':"):].split('\n')[0])
        self.assertIn("url_for('comprehensive_report')", (ROOT / 'web/templates/base.html').read_text(encoding='utf-8'))

    def test_template_parses(self):
        from jinja2 import Environment, FileSystemLoader
        Environment(loader=FileSystemLoader(str(ROOT / 'web/templates'))).parse(
            (ROOT / 'web/templates/comprehensive_report.html').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
