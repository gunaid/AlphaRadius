"""Random-MAC roaming: decision rules, worker effects and RADIUS wiring.

Isolated: no application import, database server, router or FreeRADIUS.
The real SQL function and the worker's SQL run in tests/run_roaming_mariadb_lab.py.
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


NEW_MAC = 'BB:BB:BB:BB:BB:02'


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.db = types.ModuleType('database.db')
        self.db.execute_update = Mock(return_value=1)
        self.db.execute_write = Mock()
        self.coa = types.ModuleType('services.coa_queue_service')
        self.coa.enqueue_disconnect = Mock(return_value=(True, 'queued'))
        self.modules = patch.dict(sys.modules, {'database.db': self.db, 'services.coa_queue_service': self.coa})
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def request(self, age):
        return dict(username='card', nasipaddress='10.0.0.1', callingstationid=NEW_MAC, age=age,
                    requested_at=datetime.datetime(2026, 11, 25, 10, 0, 0))

    def run_request(self, hosts, age=3, new_started=True, old=True):
        rows = ([session(7, 'AA:AA:AA:AA:AA:01', '10.5.0.2')] if old else []) + \
               ([session(8, NEW_MAC, '10.5.0.9')] if new_started else [])
        self.db.query_all = Mock(return_value=rows)
        with patch.object(roaming, '_router_hosts', return_value=hosts) as router:
            outcome = roaming.process_request(self.request(age), 20)
        self.router = router
        return outcome

    def status(self):
        return self.db.execute_update.call_args.args[1][0]

    def event(self):
        return self.db.execute_write.call_args.args[1]

    def test_idle_old_session_is_disconnected_at_once(self):
        self.assertEqual(self.run_request([host('AA:AA:AA:AA:AA:01', '10.5.0.2', '25s')]), 'kicked')
        kwargs = self.coa.enqueue_disconnect.call_args.kwargs
        self.assertEqual((kwargs['radacctid'], kwargs['mac_address'], kwargs['framed_ip'], kwargs['session_id']),
                         (7, 'AA:AA:AA:AA:AA:01', '10.5.0.2', 's7'))
        self.assertEqual(self.event(), ('card', '10.0.0.1', NEW_MAC, 'AA:AA:AA:AA:AA:01', 25, 'kicked'))
        # Only the router of the OLD session is read; the new session is never a candidate.
        self.router.assert_called_once_with('10.0.0.1', 'card')

    def test_recently_active_old_session_is_rechecked_not_judged(self):
        self.assertEqual(self.run_request([host('AA:AA:AA:AA:AA:01', '10.5.0.2', '4s')], age=10), 'waiting')
        self.coa.enqueue_disconnect.assert_not_called()
        self.db.execute_write.assert_not_called()
        self.assertEqual(self.status(), 'waiting')
        sql, params = self.db.execute_update.call_args.args
        self.assertIn("status='checking'", sql)   # a newer admission (pending) is never overwritten
        self.assertEqual(params[-1], datetime.datetime(2026, 11, 25, 10, 0, 0))

    def test_old_still_active_after_window_disconnects_the_new_session(self):
        self.assertEqual(self.run_request([host('AA:AA:AA:AA:AA:01', '10.5.0.2', '2s')], age=50), 'denied')
        kwargs = self.coa.enqueue_disconnect.call_args.kwargs
        self.assertEqual((kwargs['radacctid'], kwargs['mac_address']), (8, NEW_MAC))
        self.assertEqual(kwargs['reason'], 'Roaming: card in use on another device')
        self.assertEqual(self.event()[-1], 'denied')
        self.assertEqual(self.event()[2], NEW_MAC)   # what RADIUS reads to refuse this MAC

    def test_denial_is_recorded_even_before_the_new_session_starts(self):
        self.assertEqual(self.run_request([host('AA:AA:AA:AA:AA:01', '10.5.0.2', '2s')], age=50,
                                          new_started=False), 'denied')
        self.coa.enqueue_disconnect.assert_not_called()

    def test_old_session_gone_or_ghost_leaves_the_new_one(self):
        self.assertEqual(self.run_request([], old=False), 'freed')
        self.assertEqual(self.run_request([]), 'absent')
        self.coa.enqueue_disconnect.assert_not_called()

    def test_unreadable_router_never_disconnects(self):
        self.assertEqual(self.run_request(None, age=10), 'waiting')
        self.assertEqual(self.run_request(None, age=50), 'unverified')
        self.coa.enqueue_disconnect.assert_not_called()

    def test_full_queue_is_recorded_not_hidden(self):
        self.coa.enqueue_disconnect.return_value = (False, 'queue full')
        self.assertEqual(self.run_request([host('AA:AA:AA:AA:AA:01', '10.5.0.2', '1m')]), 'queue_failed')
        self.assertEqual(self.run_request([host('AA:AA:AA:AA:AA:01', '10.5.0.2', '1s')], age=50), 'queue_failed')

    def test_disabled_setting_processes_nothing(self):
        self.db.query_all = Mock(return_value=[{'key': 'roaming_enabled', 'value': '0'}])
        self.assertEqual(roaming.process_pending(), 0)
        self.assertEqual(self.db.query_all.call_count, 1)

    def test_only_claimed_requests_are_processed(self):
        self.db.query_all = Mock(side_effect=[[], [self.request(1)]])
        with patch.object(roaming, 'process_request') as process:
            self.assertEqual(roaming.process_pending(), 1)
        process.assert_called_once()
        self.assertEqual(process.call_args.args[1], 20)          # default threshold
        self.db.execute_update.return_value = 0                   # another worker holds it
        self.db.query_all = Mock(side_effect=[[], [self.request(1)]])
        with patch.object(roaming, 'process_request') as process:
            self.assertEqual(roaming.process_pending(), 0)
        process.assert_not_called()


class SettingsTests(unittest.TestCase):
    def test_idle_bounds_and_form_values(self):
        from services.system_settings_service import parse_roaming_idle, setting_values
        self.assertEqual(parse_roaming_idle(''), 20)
        self.assertEqual(parse_roaming_idle('10'), 10)
        for bad in ('9', '601', '-5', 'x'):
            with self.assertRaises(ValueError):
                parse_roaming_idle(bad)
        values = setting_values({'roaming_settings_present': '1', 'roaming_idle_seconds': '90'})
        self.assertEqual((values['roaming_enabled'], values['roaming_idle_seconds']), ('0', '90'))
        self.assertNotIn('roaming_enabled', setting_values({}))


class RadiusWiringTests(unittest.TestCase):
    def test_capacity_function_admits_one_extra_seat_and_records_it(self):
        from database.license_capacity import RESERVE_SQL
        limit = RESERVE_SQL.index('account_slots>=account_cap THEN')
        gate = RESERVE_SQL[limit:RESERVE_SQL.index('SET roaming_seat=1', limit)]
        for condition in ("p_station=''", 'account_slots>account_cap', "`key`='roaming_enabled'",
                          "e.outcome='denied'", 'INTERVAL 5 MINUTE'):
            self.assertIn(condition, gate)
        self.assertIn('RETURN 2', gate)
        # The request is written only after the license capacity check passed.
        record = RESERVE_SQL.index('INSERT INTO wisp_roaming_requests')
        self.assertLess(RESERVE_SQL.index('used_slots>=cap THEN RETURN 0'), record)
        self.assertLess(record, RESERVE_SQL.index('INSERT INTO wisp_session_reservations'))
        self.assertIn('fn_account_mac_allowed', RESERVE_SQL)
        self.assertNotIn('RETURN 4', RESERVE_SQL)

    def test_table_exists_before_the_function_is_installed(self):
        source = (ROOT / 'database/license_capacity.py').read_text(encoding='utf-8')
        body = source[source.index('def install_capacity_schema'):]
        self.assertLess(body.index('install_roaming_schema(cur)'), body.index('ensure_schema_object(cur, definition)'))

    def test_runtime_image_ships_the_schema(self):
        self.assertIn('database/roaming_schema.py', (ROOT / 'Dockerfile').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
