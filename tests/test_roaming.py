"""Random-MAC roaming: decision rules, worker effects and RADIUS wiring.

Isolated: no application import, database server, router or FreeRADIUS.
The real SQL function is exercised by tests/run_roaming_mariadb_lab.py.
"""
import datetime
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services import roaming_service as roaming  # noqa: E402  (imports nothing heavy at module level)


def session(rid, mac, ip, nas='10.0.0.1', protocol=''):
    return dict(radacctid=rid, nasipaddress=nas, callingstationid=mac, framedipaddress=ip,
                acctsessionid=f's{rid}', framedprotocol=protocol)


def host(mac, ip, idle):
    return {'user': 'card', 'mac-address': mac, 'address': ip, 'idle-time': idle}


class DecisionTests(unittest.TestCase):
    choose = staticmethod(roaming.choose_idle_session)

    def test_idle_old_session_is_replaced(self):
        old = session(1, 'AA:AA:AA:AA:AA:01', '10.5.0.2')
        picked, idle, outcome = self.choose([old], {'10.0.0.1': [host('aa-aa-aa-aa-aa-01', '10.5.0.2', '1m5s')]}, 45)
        self.assertEqual((picked, idle, outcome), (old, 65, 'kicked'))

    def test_live_traffic_keeps_the_session(self):
        rows = [session(1, 'AA:AA:AA:AA:AA:01', '10.5.0.2')]
        self.assertEqual(self.choose(rows, {'10.0.0.1': [host('AA:AA:AA:AA:AA:01', '10.5.0.2', '3s')]}, 45),
                         (None, None, 'live'))

    def test_threshold_is_inclusive_and_most_idle_wins(self):
        a, b = session(1, 'AA:AA:AA:AA:AA:01', '10.5.0.2'), session(2, 'AA:AA:AA:AA:AA:02', '10.5.0.3')
        routers = {'10.0.0.1': [host('AA:AA:AA:AA:AA:01', '10.5.0.2', '45s'),
                                host('AA:AA:AA:AA:AA:02', '10.5.0.3', '00:02:00')]}
        self.assertEqual(self.choose([a, b], routers, 45)[:2], (b, 120))

    def test_unreadable_router_changes_nothing(self):
        rows = [session(1, 'AA:AA:AA:AA:AA:01', '10.5.0.2')]
        self.assertEqual(self.choose(rows, {'10.0.0.1': None}, 45)[2], 'unverified')
        self.assertEqual(self.choose(rows, {'10.0.0.1': [host('AA:AA:AA:AA:AA:01', '10.5.0.2', '')]}, 45)[2],
                         'unverified')

    def test_ghost_or_ambiguous_session_is_not_replaced(self):
        rows = [session(1, 'AA:AA:AA:AA:AA:01', '10.5.0.2')]
        self.assertEqual(self.choose(rows, {'10.0.0.1': []}, 45)[2], 'absent')
        twins = [host('AA:AA:AA:AA:AA:01', '10.5.0.2', '5m')] * 2
        self.assertEqual(self.choose(rows, {'10.0.0.1': twins}, 45)[2], 'absent')
        other_ip = [host('AA:AA:AA:AA:AA:01', '10.5.9.9', '5m')]
        self.assertEqual(self.choose(rows, {'10.0.0.1': other_ip}, 45)[2], 'absent')

    def test_pppoe_is_never_replaced_and_unverified_wins_over_live(self):
        ppp = session(1, 'AA:AA:AA:AA:AA:01', '10.6.0.2', protocol='PPP')
        self.assertEqual(self.choose([ppp], {'10.0.0.1': []}, 45)[2], 'live')
        far = session(2, 'AA:AA:AA:AA:AA:02', '10.5.0.3', nas='10.0.0.9')
        self.assertEqual(self.choose([ppp, far], {'10.0.0.1': [], '10.0.0.9': None}, 45)[2], 'unverified')

    def test_routeros_durations(self):
        parse = roaming._idle_seconds
        for text, value in (('45s', 45), ('1m5s', 65), ('00:02:00', 120), ('1d02:03:04', 93784),
                            ('1w2d', 777600), ('3h', 10800), ('250ms', 0), ('2s500ms', 2)):
            self.assertEqual(parse(text), value, text)
        for bad in ('', None, 'soon', '1x', '12'):
            self.assertIsNone(parse(bad), bad)

    def test_no_open_session(self):
        self.assertEqual(self.choose([], {}, 45), (None, None, 'no_session'))


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.db = types.ModuleType('database.db')
        self.db.execute_update = Mock(return_value=1)
        self.db.execute_write = Mock()
        self.coa = types.ModuleType('services.coa_queue_service')
        self.coa.enqueue_disconnect = Mock(return_value=(True, 'queued'))
        self.request = dict(username='card', nasipaddress='10.0.0.1', callingstationid='BB:BB:BB:BB:BB:02',
                            requested_at=datetime.datetime(2026, 11, 25, 10, 0, 0))
        self.modules = patch.dict(sys.modules, {'database.db': self.db, 'services.coa_queue_service': self.coa})
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def run_request(self, hosts):
        old = session(7, 'AA:AA:AA:AA:AA:01', '10.5.0.2')
        self.db.query_all = Mock(return_value=[old])
        with patch.object(roaming, '_router_hosts', return_value=hosts):
            return roaming.process_request(self.request, 45)

    def test_idle_session_goes_through_verified_disconnect(self):
        self.assertEqual(self.run_request([host('AA:AA:AA:AA:AA:01', '10.5.0.2', '2m')]), 'kicked')
        args, kwargs = self.coa.enqueue_disconnect.call_args
        self.assertEqual(args, ('card',))
        self.assertEqual(kwargs['radacctid'], 7)
        self.assertEqual((kwargs['nas_ip'], kwargs['framed_ip'], kwargs['mac_address'], kwargs['session_id']),
                         ('10.0.0.1', '10.5.0.2', 'AA:AA:AA:AA:AA:01', 's7'))
        event = self.db.execute_write.call_args.args[1]
        self.assertEqual(event, ('card', '10.0.0.1', 'BB:BB:BB:BB:BB:02', 'AA:AA:AA:AA:AA:01', 120, 'kicked'))
        # The final update only applies to this claim; a newer reject stays pending.
        sql, params = self.db.execute_update.call_args.args
        self.assertIn("status='checking'", sql)
        self.assertEqual(params[-1], self.request['requested_at'])

    def test_live_session_is_kept(self):
        self.assertEqual(self.run_request([host('AA:AA:AA:AA:AA:01', '10.5.0.2', '2s')]), 'live')
        self.coa.enqueue_disconnect.assert_not_called()
        self.assertEqual(self.db.execute_write.call_args.args[1][-1], 'live')

    def test_full_queue_is_recorded_not_hidden(self):
        self.coa.enqueue_disconnect.return_value = (False, 'queue full')
        self.assertEqual(self.run_request([host('AA:AA:AA:AA:AA:01', '10.5.0.2', '2m')]), 'queue_failed')

    def test_disabled_setting_processes_nothing(self):
        self.db.query_all = Mock(return_value=[{'key': 'roaming_enabled', 'value': '0'}])
        self.assertEqual(roaming.process_pending(), 0)
        self.assertEqual(self.db.query_all.call_count, 1)

    def test_claim_and_recheck_window(self):
        roaming._last_check.clear()
        calls = []
        self.db.query_all = Mock(side_effect=[[], [self.request]] * 2)
        with patch.object(roaming, 'process_request', side_effect=lambda r, t: calls.append((r['username'], t))):
            self.assertEqual(roaming.process_pending(), 1)
            self.assertEqual(roaming.process_pending(), 0)   # same account within 5 s
        self.assertEqual(calls, [('card', 45)])
        self.db.execute_update.return_value = 0            # another worker claimed it
        roaming._last_check.clear()
        self.db.query_all = Mock(side_effect=[[], [self.request]])
        with patch.object(roaming, 'process_request') as process:
            self.assertEqual(roaming.process_pending(), 0)
        process.assert_not_called()


class SettingsTests(unittest.TestCase):
    def test_idle_bounds_and_form_values(self):
        from services.system_settings_service import parse_roaming_idle, setting_values
        self.assertEqual(parse_roaming_idle(''), 45)
        self.assertEqual(parse_roaming_idle('10'), 10)
        for bad in ('9', '601', '-5', 'x'):
            with self.assertRaises(ValueError):
                parse_roaming_idle(bad)
        values = setting_values({'roaming_settings_present': '1', 'roaming_idle_seconds': '90',
                                 'radius_msg_roaming': '  retry   soon '})
        self.assertEqual((values['roaming_enabled'], values['roaming_idle_seconds']), ('0', '90'))
        self.assertEqual(values['radius_msg_roaming'], 'retry soon')
        self.assertNotIn('roaming_enabled', setting_values({}))


class RadiusWiringTests(unittest.TestCase):
    def test_capacity_function_records_request_and_rejects_with_four(self):
        from database.license_capacity import RESERVE_SQL
        limit = RESERVE_SQL.index('account_slots>=account_cap THEN')
        branch = RESERVE_SQL[limit:RESERVE_SQL.index('\n END IF;', limit)]
        self.assertIn("`key`='roaming_enabled'", branch)
        self.assertIn('INSERT INTO wisp_roaming_requests', branch)
        self.assertLess(branch.index('RETURN 4'), branch.index('RETURN 2'))
        # The roaming branch never reserves a seat.
        self.assertNotIn('wisp_session_reservations', branch)
        self.assertIn('fn_account_mac_allowed', RESERVE_SQL)

    def test_table_exists_before_the_function_is_installed(self):
        source = (ROOT / 'database/license_capacity.py').read_text(encoding='utf-8')
        body = source[source.index('def install_capacity_schema'):]
        self.assertLess(body.index('install_roaming_schema(cur)'), body.index('ensure_schema_object(cur, definition)'))

    def test_postauth_message_and_defaults(self):
        from database.radius_message_schema import DEFAULTS, FUNCTION_SQL
        postauth = (ROOT / 'docker/freeradius/license-capacity-postauth.conf').read_text(encoding='utf-8')
        branch = postauth[postauth.index('Tmp-String-1 == "4"'):postauth.index('Tmp-String-1 == "2"')]
        self.assertIn("SELECT fn_rmsg('roaming')", branch)
        self.assertIn('roaming', dict(DEFAULTS))
        self.assertIn("WHEN 'roaming' THEN", FUNCTION_SQL)

    def test_runtime_image_ships_the_schema(self):
        self.assertIn('database/roaming_schema.py', (ROOT / 'Dockerfile').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
