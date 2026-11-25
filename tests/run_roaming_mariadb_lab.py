"""Explicit synthetic MariaDB lab for random-MAC roaming; no application, NAS or FreeRADIUS.

Runs the real fn_reserve_license_slot, fn_cloned_mac_profile, fn_realm_policy,
fn_record_realm_choice, the roaming
worker's SQL and the cloned-MAC detection query against
a dedicated, disposable database:

    DB_HOST=... DB_USER=... DB_PASSWORD=... DB_NAME=roaming_fixture \\
        python tests/run_roaming_mariadb_lab.py --run

(DB_SOCKET may replace DB_HOST.) It refuses any other database name and drops
and recreates only the fixture tables it owns. The router is simulated.
"""
import datetime
import hashlib
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DB = 'roaming_fixture'
TABLES = ('wisp_license_runtime_state', 'wisp_license_info', 'wisp_revoked_licenses', 'wisp_renewal_guards',
          'radcheck', 'radgroupcheck', 'radusergroup', 'radacct', 'wisp_session_reservations',
          'wisp_system_settings', 'wisp_roaming_requests', 'wisp_roaming_events',
          'wisp_cloned_macs', 'wisp_cloned_mac_profiles', 'wisp_realm_choices')


def connect():
    import pymysql
    options = dict(user=os.environ['DB_USER'], password=os.environ.get('DB_PASSWORD', ''), database=FIXTURE_DB,
                   charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor, autocommit=True)
    if os.environ.get('DB_SOCKET'):
        options['unix_socket'] = os.environ['DB_SOCKET']
    else:
        options['host'] = os.environ['DB_HOST']
    return pymysql.connect(**options)


def build(cur):
    from database.license_capacity import CHECK_SQL, RESERVE_SQL
    from database.roaming_schema import install_roaming_schema
    # Production tables are utf8mb4_unicode_ci; so are the function parameters.
    cur.execute('ALTER DATABASE ' + FIXTURE_DB + ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
    for table in TABLES:
        cur.execute('DROP TABLE IF EXISTS ' + table)
    cur.execute("""CREATE TABLE wisp_license_runtime_state(id INT PRIMARY KEY, license_row_id INT, package_hash CHAR(64),
        is_valid TINYINT, license_mode VARCHAR(32), max_active_sessions INT, valid_until DATETIME)""")
    cur.execute('CREATE TABLE wisp_license_info(id INT PRIMARY KEY, license_id VARCHAR(64), raw_package_json TEXT, status VARCHAR(16))')
    cur.execute('CREATE TABLE wisp_revoked_licenses(license_id VARCHAR(64))')
    cur.execute('CREATE TABLE wisp_renewal_guards(username VARCHAR(64), expires_at DATETIME)')
    for table in ('radcheck', 'radgroupcheck'):
        cur.execute(f'CREATE TABLE {table}(id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(64), groupname VARCHAR(64), attribute VARCHAR(64), value VARCHAR(253))')
    cur.execute('CREATE TABLE radusergroup(username VARCHAR(64), groupname VARCHAR(64))')
    cur.execute("""CREATE TABLE radacct(radacctid BIGINT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(64), nasipaddress VARCHAR(45),
        callingstationid VARCHAR(50), framedipaddress VARCHAR(45), acctsessionid VARCHAR(64), framedprotocol VARCHAR(32),
        nasportid VARCHAR(50), acctstarttime DATETIME, acctupdatetime DATETIME, acctstoptime DATETIME,
        acctsessiontime INT)""")
    cur.execute("""CREATE TABLE wisp_session_reservations(id INT AUTO_INCREMENT PRIMARY KEY, session_key CHAR(32) UNIQUE,
        username VARCHAR(64), nasipaddress VARCHAR(45), callingstationid VARCHAR(50), nasportid VARCHAR(50),
        reserved_at DATETIME, expires_at DATETIME, radacctid BIGINT NULL)""")
    cur.execute('CREATE TABLE wisp_system_settings(`key` VARCHAR(100) PRIMARY KEY, `value` TEXT, description TEXT)')
    install_roaming_schema(cur)
    from database.cloned_mac_schema import install_cloned_mac_schema
    install_cloned_mac_schema(cur)
    from database.realm_policy_schema import install_realm_policy_schema
    install_realm_policy_schema(cur)
    cur.execute("CREATE OR REPLACE FUNCTION fn_account_mac_allowed(u VARCHAR(64), s VARCHAR(50)) RETURNS INT DETERMINISTIC RETURN 1")
    cur.execute(CHECK_SQL)
    cur.execute(RESERVE_SQL)
    raw = json.dumps({'payload': {'license_id': 'fixture'}})
    cur.execute("INSERT INTO wisp_license_info VALUES (1,'fixture',%s,'active')", (raw,))
    cur.execute("""INSERT INTO wisp_license_runtime_state VALUES (1,1,%s,1,'active_sessions',100,UTC_TIMESTAMP()+INTERVAL 1 HOUR)""",
                (hashlib.sha256(raw.encode()).hexdigest(),))


def stub_database_module(conn):
    """database.db over the fixture connection, '?' placeholders like the app."""
    def run(sql, args=(), mode='all'):
        with conn.cursor() as cur:
            cur.execute(sql.replace('?', '%s'), args)
            if mode == 'all':
                return list(cur.fetchall())
            return cur.rowcount if mode == 'count' else cur.lastrowid
    db = types.ModuleType('database.db')
    db.query_all = lambda sql, args=(): run(sql, args)
    db.execute_update = lambda sql, args=(): run(sql, args, 'count')
    db.execute_write = lambda sql, args=(): run(sql, args, 'id')
    return db


class RoamingLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = connect()
        cls.cur = cls.conn.cursor()
        with cls.cur as cur:
            cur.execute('SELECT DATABASE() AS name')
            assert cur.fetchone()['name'] == FIXTURE_DB
        cls.cur = cls.conn.cursor()
        build(cls.cur)

    def setUp(self):
        for table in ('radcheck', 'radacct', 'wisp_session_reservations', 'wisp_roaming_requests',
                      'wisp_roaming_events', 'wisp_system_settings', 'wisp_cloned_macs', 'wisp_cloned_mac_profiles'):
            self.cur.execute('DELETE FROM ' + table)
        self.cur.execute("INSERT INTO radcheck(username,attribute,value) VALUES ('card','Simultaneous-Use','1')")
        self.key = 0

    def reserve(self, station, user='card'):
        self.key += 1
        self.cur.execute("SELECT fn_reserve_license_slot(%s,%s,'10.0.0.1',%s,'1','10.0.0.1') AS r",
                         (f'{self.key:032x}', user, station))
        return self.cur.fetchone()['r']

    def open_session(self, mac='AA:AA:AA:AA:AA:01', ip='10.5.0.2'):
        self.cur.execute("""INSERT INTO radacct(username,nasipaddress,callingstationid,framedipaddress,acctsessionid,
            framedprotocol,nasportid,acctstarttime,acctupdatetime) VALUES ('card','10.0.0.1',%s,%s,'s1','','vlan10',NOW(),NOW())""",
                         (mac, ip))
        return self.cur.lastrowid

    def request(self):
        self.cur.execute("SELECT * FROM wisp_roaming_requests WHERE username='card'")
        return self.cur.fetchone()

    def seats(self):
        self.cur.execute("SELECT COUNT(*) AS n FROM wisp_session_reservations WHERE username='card'")
        return self.cur.fetchone()['n']

    def test_first_login_reserves_a_seat(self):
        self.assertEqual(self.reserve('AA:AA:AA:AA:AA:01'), 1)
        self.assertIsNone(self.request())

    def test_new_mac_at_limit_is_admitted_on_one_extra_seat(self):
        self.open_session()
        self.assertEqual(self.reserve('BB:BB:BB:BB:BB:02'), 1)
        row = self.request()
        self.assertEqual((row['status'], row['callingstationid'], row['nasipaddress']),
                         ('pending', 'BB:BB:BB:BB:BB:02', '10.0.0.1'))
        self.assertEqual(self.seats(), 1)
        # Never more than one temporary extra seat: a third device is refused.
        self.assertEqual(self.reserve('CC:CC:CC:CC:CC:03'), 2)
        self.assertEqual(self.request()['callingstationid'], 'BB:BB:BB:BB:BB:02')

    def test_denied_mac_is_refused_for_five_minutes(self):
        self.open_session()
        self.cur.execute("""INSERT INTO wisp_roaming_events(username,new_mac,outcome,created_at)
                            VALUES ('card','BB:BB:BB:BB:BB:02','denied',NOW()-INTERVAL 1 MINUTE)""")
        self.assertEqual(self.reserve('BB:BB:BB:BB:BB:02'), 2)
        self.assertEqual(self.seats(), 0)
        self.cur.execute("UPDATE wisp_roaming_events SET created_at=NOW()-INTERVAL 6 MINUTE")
        self.assertEqual(self.reserve('BB:BB:BB:BB:BB:02'), 1)

    def test_disabled_or_unknown_mac_keeps_the_plain_limit(self):
        self.open_session()
        self.cur.execute("INSERT INTO wisp_system_settings(`key`,`value`) VALUES ('roaming_enabled','0')")
        self.assertEqual(self.reserve('BB:BB:BB:BB:BB:02'), 2)
        self.cur.execute("DELETE FROM wisp_system_settings")
        self.assertEqual(self.reserve(''), 2)
        self.assertIsNone(self.request())

    def test_license_capacity_still_wins(self):
        self.open_session()
        self.cur.execute("UPDATE wisp_license_runtime_state SET max_active_sessions=1")
        try:
            self.assertEqual(self.reserve('BB:BB:BB:BB:BB:02'), 0)
            self.assertIsNone(self.request(), 'no request without an admitted seat')
        finally:
            self.cur.execute("UPDATE wisp_license_runtime_state SET max_active_sessions=100")

    def test_unlimited_account_is_unchanged(self):
        self.cur.execute("DELETE FROM radcheck")
        self.open_session()
        self.assertEqual(self.reserve('BB:BB:BB:BB:BB:02'), 1)
        self.assertIsNone(self.request())

    def run_worker(self, idle, age=None):
        from services import roaming_service as roaming
        if age is not None:
            self.cur.execute("UPDATE wisp_roaming_requests SET requested_at=NOW()-INTERVAL %s SECOND", (age,))
        coa = types.ModuleType('services.coa_queue_service')
        coa.enqueue_disconnect = Mock(return_value=(True, 'queued'))
        hosts = [{'user': 'card', 'mac-address': 'AA:AA:AA:AA:AA:01', 'address': '10.5.0.2', 'idle-time': idle}]
        with patch.dict(sys.modules, {'database.db': stub_database_module(self.conn), 'services.coa_queue_service': coa}), \
                patch.object(roaming, '_router_hosts', return_value=hosts):
            processed = roaming.process_pending()
        return processed, coa.enqueue_disconnect

    def test_idle_old_session_is_disconnected(self):
        old = self.open_session()
        self.reserve('BB:BB:BB:BB:BB:02')
        processed, enqueue = self.run_worker('25s')
        self.assertEqual(processed, 1)
        self.assertEqual(enqueue.call_args.kwargs['radacctid'], old)
        self.assertEqual((self.request()['status'], self.request()['attempts']), ('kicked', 1))
        self.cur.execute('SELECT outcome, idle_seconds, old_mac, new_mac FROM wisp_roaming_events')
        self.assertEqual(self.cur.fetchone(), {'outcome': 'kicked', 'idle_seconds': 25,
                                               'old_mac': 'AA:AA:AA:AA:AA:01', 'new_mac': 'BB:BB:BB:BB:BB:02'})
        self.assertEqual(self.run_worker('25s')[0], 0, 'a finished request is not processed again')

    def test_live_old_session_waits_then_new_is_disconnected_and_refused(self):
        self.open_session()
        self.reserve('BB:BB:BB:BB:BB:02')
        new = self.open_session('BB:BB:BB:BB:BB:02', '10.5.0.9')
        processed, enqueue = self.run_worker('3s')
        self.assertEqual((processed, self.request()['status']), (1, 'waiting'))
        enqueue.assert_not_called()
        self.assertEqual(self.run_worker('3s')[0], 0, 'rechecked only after 5 seconds')
        self.cur.execute("UPDATE wisp_roaming_requests SET processed_at=NOW()-INTERVAL 6 SECOND")
        processed, enqueue = self.run_worker('2s', age=55)
        self.assertEqual(self.request()['status'], 'denied')
        self.assertEqual(enqueue.call_args.kwargs['radacctid'], new)
        # The real function now refuses this MAC on its next attempt.
        self.cur.execute("UPDATE radacct SET acctstoptime=NOW() WHERE radacctid=%s", (new,))
        self.cur.execute("DELETE FROM wisp_session_reservations")
        self.assertEqual(self.reserve('BB:BB:BB:BB:BB:02'), 2)

    def test_stale_claim_is_retried(self):
        self.open_session()
        self.reserve('BB:BB:BB:BB:BB:02')
        self.cur.execute("UPDATE wisp_roaming_requests SET status='checking', processed_at=NOW()-INTERVAL 2 MINUTE")
        self.assertEqual(self.run_worker('5m')[0], 1)
        self.assertEqual(self.request()['status'], 'kicked')


class ClonedMacLab(RoamingLab):
    """Reuses the fixture; only its own cases run here."""
    def profile(self, station, nas='10.0.0.1', group='pkg-2M'):
        self.cur.execute('SELECT fn_cloned_mac_profile(%s,%s,%s) AS p', (station, nas, group))
        return self.cur.fetchone()['p']

    def setUp(self):
        super().setUp()
        self.cur.execute("INSERT INTO wisp_cloned_macs(mac,created_at) VALUES ('AA:AA:AA:AA:AA:01',NOW())")
        self.cur.execute("""INSERT INTO wisp_cloned_mac_profiles VALUES ('10.0.0.1','pkg-2M-nocookie',NOW()),
                            ('10.0.0.1','default-nocookie',NOW())""")

    def test_profile_needs_the_feature_the_list_and_a_confirmed_copy(self):
        self.assertEqual(self.profile('AA:AA:AA:AA:AA:01'), '', 'feature off by default')
        self.cur.execute("INSERT INTO wisp_system_settings(`key`,`value`) VALUES ('cloned_mac_enabled','1')")
        self.assertEqual(self.profile('AA:AA:AA:AA:AA:01'), 'pkg-2M-nocookie')
        self.assertEqual(self.profile('aa-aa-aa-aa-aa-01'), 'pkg-2M-nocookie')
        self.assertEqual(self.profile('AA:AA:AA:AA:AA:01', group=''), 'default-nocookie')
        self.assertEqual(self.profile('AA:AA:AA:AA:AA:01', group='pkg-9M'), '', 'copy not on this router')
        self.assertEqual(self.profile('AA:AA:AA:AA:AA:01', nas='10.0.0.2'), '', 'other router not synced')
        self.assertEqual(self.profile('BB:BB:BB:BB:BB:02'), '', 'unlisted MAC unchanged')
        self.assertEqual(self.profile(''), '')

    def test_operator_seed_was_inserted_once(self):
        from database.cloned_mac_schema import SEED_MACS, SEED_FLAG, seed_cloned_macs
        self.cur.execute('DELETE FROM wisp_cloned_macs')
        self.assertEqual(seed_cloned_macs(self.cur), len(SEED_MACS))
        self.cur.execute("SELECT COUNT(*) AS n FROM wisp_cloned_macs WHERE source='preset'")
        self.assertEqual(self.cur.fetchone()['n'], 49)
        self.assertEqual(seed_cloned_macs(self.cur), 0, 'flag stops a second seed')
        self.cur.execute("SELECT `value` FROM wisp_system_settings WHERE `key`=%s", (SEED_FLAG,))
        self.assertEqual(self.cur.fetchone()['value'], '49')

    def test_listed_mac_keeps_the_plain_limit(self):
        self.open_session('CC:CC:CC:CC:CC:03')
        self.assertEqual(self.reserve('AA:AA:AA:AA:AA:01'), 2)
        self.assertIsNone(self.request())
        self.assertEqual(self.reserve('BB:BB:BB:BB:BB:02'), 1, 'other MACs still roam')

    def test_detection_query(self):
        from services import cloned_mac_service as cloned
        rows = [  # (user, mac, port, open, seconds)
            ('c1', 'DD:DD:DD:DD:DD:04', 'vlan10', False, 600), ('c2', 'DD:DD:DD:DD:DD:04', 'vlan10', False, 600),
            ('c3', 'dd-dd-dd-dd-dd-04', 'vlan20', False, 600),
            ('c4', 'EE:EE:EE:EE:EE:05', 'vlan10', True, None), ('c4', 'EE:EE:EE:EE:EE:05', 'vlan10', True, None),
            ('c5', 'FF:FF:FF:FF:FF:06', 'vlan10', False, 900)]
        for user, mac, port, is_open, seconds in rows:
            self.cur.execute("""INSERT INTO radacct(username,nasipaddress,callingstationid,nasportid,acctstarttime,
                acctstoptime,acctsessiontime) VALUES (%s,'10.0.0.1',%s,%s,NOW()-INTERVAL 1 HOUR,%s,%s)""",
                             (user, mac, port, None if is_open else datetime.datetime.now(), seconds))
        self.cur.execute("""INSERT INTO radacct(username,nasipaddress,callingstationid,nasportid,acctstarttime,acctstoptime)
            VALUES ('old','10.0.0.1','99:99:99:99:99:99','vlan1',NOW()-INTERVAL 30 DAY,NOW()-INTERVAL 30 DAY)""")
        self.cur.execute("INSERT INTO wisp_cloned_macs(mac,created_at) VALUES ('DD:DD:DD:DD:DD:04',NOW())")
        with patch.dict(sys.modules, {'database.db': stub_database_module(self.conn)}):
            found = {r['mac']: r for r in cloned.detect(dict(days=7, min_cards=3, min_ports=2, min_short=20))}
        self.assertEqual(sorted(found), ['DD:DD:DD:DD:DD:04', 'EE:EE:EE:EE:EE:05'])
        self.assertEqual((found['DD:DD:DD:DD:DD:04']['cards'], found['DD:DD:DD:DD:DD:04']['ports']), (3, 2))
        self.assertTrue(found['DD:DD:DD:DD:DD:04']['listed'])
        self.assertEqual(int(found['EE:EE:EE:EE:EE:05']['open_now']), 2)
        self.assertIn('جلسات مفتوحة معًا', found['EE:EE:EE:EE:EE:05']['reasons'])


class RealmLab(RoamingLab):
    def policy(self, realm):
        self.cur.execute('SELECT fn_realm_policy(%s) AS p', (realm,))
        return self.cur.fetchone()['p']

    def test_domain_grammar(self):
        cases = {'512k/2m|yes': '512k/2M;block-updates', '512k/2m=7Cyes': '512k/2M;block-updates',
                 '1M/4M_yes': '1M/4M;block-updates', '2M/8M': '2M/8M;', 'yes': ';block-updates', 'no': ';',
                 '1.5M/3M': '1.5M/3M;', '0/0|yes': ';block-updates',
                 'abc': '', '512k_2M': '', 'example.com': '', '512k/2M|yes|no|yes|1': '', '': '', None: ''}
        for realm, expected in cases.items():
            self.assertEqual(self.policy(realm), expected, realm)

    def test_settings_change_effects_not_validity(self):
        self.cur.execute("INSERT INTO wisp_system_settings(`key`,`value`) VALUES ('realm_block_list','no-updates')")
        self.assertEqual(self.policy('2M/8M|yes'), '2M/8M;no-updates')
        self.cur.execute("INSERT INTO wisp_system_settings(`key`,`value`) VALUES ('realm_speed_enabled','0')")
        self.assertEqual(self.policy('2M/8M|yes'), ';', 'still valid, so the name is stripped, but no effect')
        self.assertEqual(self.policy('abc'), '')

    def test_choice_is_recorded_from_escaped_values(self):
        self.cur.execute('DELETE FROM wisp_realm_choices')
        self.cur.execute("SELECT fn_record_realm_choice('card1','10.0.0.1','AA:AA:AA:AA:AA:01','512k/2m=7Cyes','512k/2M=3Bblock-updates') r")
        self.assertEqual(self.cur.fetchone()['r'], 1)
        self.cur.execute("SELECT fn_record_realm_choice('card1','10.0.0.1','AA:AA:AA:AA:AA:01','2M/8M','2M/8M;') r")
        self.cur.execute('SELECT username,realm,rate,block_updates FROM wisp_realm_choices')
        self.assertEqual(self.cur.fetchall(), [{'username': 'card1', 'realm': '2M/8M', 'rate': '2M/8M', 'block_updates': 0}])


def _only_own_cases():
    # ClonedMacLab inherits RoamingLab's cases; drop them so each runs once.
    for name in [n for n in vars(RoamingLab) if n.startswith('test_')]:
        setattr(ClonedMacLab, name, None)
        setattr(RealmLab, name, None)


_only_own_cases()


def main():
    if sys.argv[1:] != ['--run'] or os.environ.get('DB_NAME') != FIXTURE_DB:
        raise SystemExit(f'Requires --run and the dedicated {FIXTURE_DB} database')
    sys.path.insert(0, str(ROOT))
    result = unittest.main(argv=[sys.argv[0], '-v'], exit=False).result
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
