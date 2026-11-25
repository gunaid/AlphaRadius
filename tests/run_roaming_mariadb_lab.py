"""Explicit synthetic MariaDB lab for random-MAC roaming; no application, NAS or FreeRADIUS.

Runs the real fn_reserve_license_slot and the roaming worker's own SQL against
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
          'wisp_system_settings', 'wisp_roaming_requests', 'wisp_roaming_events')


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
        nasportid VARCHAR(50), acctstarttime DATETIME, acctupdatetime DATETIME, acctstoptime DATETIME)""")
    cur.execute("""CREATE TABLE wisp_session_reservations(id INT AUTO_INCREMENT PRIMARY KEY, session_key CHAR(32) UNIQUE,
        username VARCHAR(64), nasipaddress VARCHAR(45), callingstationid VARCHAR(50), nasportid VARCHAR(50),
        reserved_at DATETIME, expires_at DATETIME, radacctid BIGINT NULL)""")
    cur.execute('CREATE TABLE wisp_system_settings(`key` VARCHAR(100) PRIMARY KEY, `value` TEXT, description TEXT)')
    install_roaming_schema(cur)
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
                      'wisp_roaming_events', 'wisp_system_settings'):
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

    def test_first_login_reserves_a_seat(self):
        self.assertEqual(self.reserve('AA:AA:AA:AA:AA:01'), 1)
        self.assertIsNone(self.request())

    def test_new_mac_at_limit_is_rejected_with_a_roaming_request(self):
        self.open_session()
        self.assertEqual(self.reserve('BB:BB:BB:BB:BB:02'), 4)
        row = self.request()
        self.assertEqual((row['status'], row['callingstationid'], row['nasipaddress']),
                         ('pending', 'BB:BB:BB:BB:BB:02', '10.0.0.1'))
        self.cur.execute("SELECT COUNT(*) AS n FROM wisp_session_reservations")
        self.assertEqual(self.cur.fetchone()['n'], 0, 'a roaming reject must not reserve a seat')

    def test_retry_requeues_the_single_row(self):
        self.open_session()
        self.reserve('BB:BB:BB:BB:BB:02')
        self.cur.execute("UPDATE wisp_roaming_requests SET status='live', requested_at=NOW()-INTERVAL 1 MINUTE")
        self.assertEqual(self.reserve('CC:CC:CC:CC:CC:03'), 4)
        self.cur.execute("SELECT COUNT(*) AS n, MAX(status) AS status, MAX(callingstationid) AS mac FROM wisp_roaming_requests")
        self.assertEqual(self.cur.fetchone(), {'n': 1, 'status': 'pending', 'mac': 'CC:CC:CC:CC:CC:03'})

    def test_disabled_or_unknown_mac_keeps_the_plain_limit(self):
        self.open_session()
        self.cur.execute("INSERT INTO wisp_system_settings(`key`,`value`) VALUES ('roaming_enabled','0')")
        self.assertEqual(self.reserve('BB:BB:BB:BB:BB:02'), 2)
        self.cur.execute("DELETE FROM wisp_system_settings")
        self.assertEqual(self.reserve(''), 2)
        self.assertIsNone(self.request())

    def test_unlimited_account_is_unchanged(self):
        self.cur.execute("DELETE FROM radcheck")
        self.open_session()
        self.assertEqual(self.reserve('BB:BB:BB:BB:BB:02'), 1)

    def run_worker(self, idle):
        from services import roaming_service as roaming
        coa = types.ModuleType('services.coa_queue_service')
        coa.enqueue_disconnect = Mock(return_value=(True, 'queued'))
        hosts = [{'user': 'card', 'mac-address': 'AA:AA:AA:AA:AA:01', 'address': '10.5.0.2', 'idle-time': idle}]
        roaming._last_check.clear()
        with patch.dict(sys.modules, {'database.db': stub_database_module(self.conn), 'services.coa_queue_service': coa}), \
                patch.object(roaming, '_router_hosts', return_value=hosts):
            processed = roaming.process_pending()
        return processed, coa.enqueue_disconnect

    def test_worker_sql_kicks_idle_and_keeps_live(self):
        rid = self.open_session()
        self.reserve('BB:BB:BB:BB:BB:02')
        processed, enqueue = self.run_worker('2m10s')
        self.assertEqual(processed, 1)
        self.assertEqual(enqueue.call_args.kwargs['radacctid'], rid)
        row = self.request()
        self.assertEqual((row['status'], row['attempts']), ('kicked', 1))
        self.cur.execute('SELECT outcome, idle_seconds, old_mac, new_mac FROM wisp_roaming_events')
        self.assertEqual(self.cur.fetchone(), {'outcome': 'kicked', 'idle_seconds': 130,
                                               'old_mac': 'AA:AA:AA:AA:AA:01', 'new_mac': 'BB:BB:BB:BB:BB:02'})
        self.assertEqual(self.run_worker('2m10s')[0], 0, 'a finished request is not processed again')
        self.reserve('BB:BB:BB:BB:BB:02')
        processed, enqueue = self.run_worker('4s')
        self.assertEqual(processed, 1)
        enqueue.assert_not_called()
        self.assertEqual(self.request()['status'], 'live')

    def test_stale_claim_is_retried(self):
        self.open_session()
        self.reserve('BB:BB:BB:BB:BB:02')
        self.cur.execute("UPDATE wisp_roaming_requests SET status='checking', processed_at=NOW()-INTERVAL 2 MINUTE")
        self.assertEqual(self.run_worker('5m')[0], 1)
        self.assertEqual(self.request()['status'], 'kicked')


def main():
    if sys.argv[1:] != ['--run'] or os.environ.get('DB_NAME') != FIXTURE_DB:
        raise SystemExit(f'Requires --run and the dedicated {FIXTURE_DB} database')
    sys.path.insert(0, str(ROOT))
    result = unittest.main(argv=[sys.argv[0], '-v'], exit=False).result
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
