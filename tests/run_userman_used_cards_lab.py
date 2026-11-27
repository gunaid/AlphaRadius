"""MariaDB lab: User Manager 6 used cards ('restart' mode) and package groups.

Needs a disposable database named userman_used_lab with the application schema
(e.g. ``mysql userman_used_lab < database/schema_mysql.sql``):

    DB_TYPE=mysql DB_HOST=127.0.0.1 DB_USER=... DB_PASSWORD=... DB_NAME=userman_used_lab \\
        python tests/run_userman_used_cards_lab.py --run

Imports synthetic User Manager rows with execute_userman_import (the code the
import pages call), then runs Core's real authorize_check_query from
docker/freeradius/queries.conf for each card and reads its reject rows
(quota 999999, uptime 999997, reconciliation 999990, status 999995).
No router, no RADIUS traffic, no tenant data.
"""
import datetime
import os
import re
import sys
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MB = 1048576


def authorize_check_sql():
    text = (ROOT / 'docker/freeradius/queries.conf').read_text(encoding='utf-8')
    start = text.index('\nauthorize_check_query = "\\\n') + len('\nauthorize_check_query = "\\\n')
    body = text[start:text.index('"\n', start)]
    return body.replace('\\\n', '\n')


def main():
    if sys.argv[1:] != ['--run'] or os.environ.get('DB_NAME') != 'userman_used_lab':
        raise SystemExit('Only userman_used_lab with --run is allowed')
    sys.path.insert(0, str(ROOT))
    # No licensing server or bot notifications in this local suite (as in userman_rootfix_mariadb).
    import types
    license_module = types.ModuleType('services.license_guard_service')
    license_module.get_active_license_status = lambda **kw: None
    sys.modules['services.license_guard_service'] = license_module
    import core.license_feature_policy as feature
    feature.verified_state = lambda *a, **k: dict(valid=True, status='active', features={}, limits={})
    from database.db import get_connection
    from database.userman_import_schema import install_userman_import_schema
    from services.mikrotik_userman_importer import execute_userman_import
    import services.mikrotik_userman_importer as importer
    importer.log_audit = lambda *a, **k: None
    from services.userman_import_journal import rollback_import
    from database.db import init_database
    init_database()                      # runtime views/tables Core queries use, as at server start
    conn = get_connection()
    install_userman_import_schema(conn)
    conn.close()
    check_sql = authorize_check_sql()

    def rows(sql, args=()):
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, args)
                return list(cur.fetchall())
        finally:
            conn.close()

    def write(sql, args=()):
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, args)
            conn.commit()
        finally:
            conn.close()

    def rejects(username):
        assert re.fullmatch(r'[a-z0-9_]+', username)
        found = rows(check_sql.replace('%{SQL-User-Name}', username))
        return sorted({r['id'] for r in found if r['attribute'] == 'Auth-Type' and r['value'] == 'Reject'})

    tag = uuid.uuid4().hex[:6]
    profile = f'lab100_{tag}'

    def payload(names, group='hs-100'):
        used = dict(uptime_used_mins=325, uptime_used_seconds=5 * 3600 + 25 * 60 + 26,
                    download_used_bytes=219415946, upload_used_bytes=27337694)
        exhausted = dict(uptime_used_mins=60, uptime_used_seconds=3600,
                         download_used_bytes=301 * MB, upload_used_bytes=0)
        users = []
        for kind, name in names.items():
            row = dict(username=name, password='', actual_profile=profile, has_profile=True, caller_id='',
                       comment='', email='', phone='', shared_users=1, disabled=False,
                       uptime_used_mins=0, uptime_used_seconds=0, download_used_bytes=0, upload_used_bytes=0,
                       first_used_at='', last_renewed_at='', till_time='')
            row.update(used if kind in ('used', 'used_open') else exhausted if kind == 'exhausted' else {})
            users.append(row)
        return dict(profiles=[dict(name=profile, name_for_users=profile, price=100, validity_value=2,
                                   validity_unit='days', rate_down='', rate_up='', quota_mb=300,
                                   uptime_mins=420, override_shared_users=1, group_name=group)],
                    users=users)

    class Cases(unittest.TestCase):
        maxDiff = None

        def test_1_default_mode_keeps_used_cards_for_review(self):
            names = {'used': f'r_used_{tag}', 'unused': f'r_new_{tag}'}
            result = execute_userman_import(payload(names), import_consumption=True, operation_id=uuid.uuid4().hex)
            self.assertTrue(result['success'], result)
            self.assertEqual(result['stats']['created_users'], 1)
            self.assertEqual(result['stats']['review_required_users'], 1)
            self.assertEqual(rows('SELECT COUNT(*) n FROM wisp_vouchers WHERE username=%s', (names['used'],))[0]['n'], 0)

        def test_2_package_group_reaches_package_card_and_radius(self):
            pkg = rows('SELECT id, mikrotik_group FROM wisp_packages WHERE name=%s', (profile,))
            self.assertEqual(pkg[0]['mikrotik_group'], 'hs-100')
            reply = rows("SELECT value FROM radgroupreply WHERE groupname=%s AND attribute='Mikrotik-Group'", (profile,))
            self.assertEqual([r['value'] for r in reply], ['hs-100'])
            snap = rows('SELECT snap_mikrotik_group FROM wisp_vouchers WHERE username=%s', (f'r_new_{tag}',))
            self.assertEqual(snap[0]['snap_mikrotik_group'], 'hs-100')

        def test_3_restart_mode_imports_used_cards_with_remaining_balance(self):
            names = {'used': f'u_used_{tag}', 'used_open': f'u_open_{tag}', 'exhausted': f'u_full_{tag}', 'unused': f'u_new_{tag}'}
            # Accounting already sent here for a session User Manager authenticated (still open).
            start = datetime.datetime.now().replace(microsecond=0) - datetime.timedelta(minutes=30)
            write('''INSERT INTO radacct(acctsessionid,acctuniqueid,username,nasipaddress,acctstarttime,acctupdatetime,
                     acctsessiontime,acctinputoctets,acctoutputoctets,callingstationid,framedipaddress)
                     VALUES(%s,%s,%s,'3.3.3.1',%s,%s,1800,%s,%s,'AA:BB:CC:00:00:01','10.0.0.9')''',
                  ('S' + tag, uuid.uuid4().hex, names['used_open'], start, start, 10 * MB, 20 * MB))
            job = uuid.uuid4().hex
            result = execute_userman_import(payload(names), import_consumption=False, used_cards_mode='restart', operation_id=job)
            self.assertTrue(result['success'], result)
            st = result['stats']
            self.assertEqual((st['created_users'], st['restarted_used_users'], st['review_required_users']), (4, 3, 0))

            cards = {r['username']: r for r in rows(
                'SELECT username,status,first_used_at,last_renewed_at,expires_at,snap_mikrotik_group FROM wisp_vouchers WHERE username IN (%s,%s,%s,%s)',
                tuple(names.values()))}
            used = cards[names['used']]
            self.assertEqual(used['status'], 'active')
            self.assertEqual(used['first_used_at'], used['last_renewed_at'])
            self.assertEqual(used['expires_at'] - used['last_renewed_at'], datetime.timedelta(days=2), 'validity from import')
            db_now = rows('SELECT CURRENT_TIMESTAMP n')[0]['n']
            self.assertLess(abs((used['last_renewed_at'] - db_now).total_seconds()), 120, 'cycle starts at import time')
            self.assertEqual(cards[names['exhausted']]['status'], 'expired')
            self.assertEqual(cards[names['unused']]['status'], 'unused')
            self.assertIsNone(cards[names['unused']]['first_used_at'])

            baseline = rows("SELECT acctinputoctets i, acctoutputoctets o, acctsessiontime t, acctstarttime s FROM radacct WHERE username=%s AND acctterminatecause='Consolidated-Historical-Import'", (names['used'],))
            self.assertEqual((baseline[0]['i'], baseline[0]['o'], baseline[0]['t']), (27337694, 219415946, 19526))
            self.assertEqual(baseline[0]['s'], used['last_renewed_at'])
            self.assertEqual(rows("SELECT COUNT(*) n FROM radacct WHERE username=%s", (names['unused'],))[0]['n'], 0)
            radcheck = {r['attribute'] for r in rows('SELECT attribute FROM radcheck WHERE username=%s', (names['used'],))}
            self.assertEqual(radcheck, {'Cleartext-Password', 'Expiration'})
            self.assertIn('Reject', {r['value'] for r in rows('SELECT value FROM radcheck WHERE username=%s', (names['exhausted'],))})

            open_baseline = rows('SELECT baseline_input_bytes i, baseline_output_bytes o, baseline_seconds t, renewed_at FROM wisp_session_baselines WHERE username=%s', (names['used_open'],))
            open_card = rows('SELECT last_renewed_at FROM wisp_vouchers WHERE username=%s', (names['used_open'],))[0]
            self.assertEqual((open_baseline[0]['i'], open_baseline[0]['o'], open_baseline[0]['t']), (10 * MB, 20 * MB, 1800))
            self.assertEqual(open_baseline[0]['renewed_at'], open_card['last_renewed_at'])

            # Core's own authorization SQL on the imported state.
            self.assertEqual(rejects(names['used']), [], '235 MB of 300 MB and 5h25m of 7h used: login allowed')
            self.assertEqual(rejects(names['used_open']), [], 'open pre-import session: no reconciliation reject')
            self.assertEqual(rejects(names['unused']), [])
            self.assertTrue(rejects(names['exhausted']), 'data limit already used')

            # More traffic after import counts against the remaining 64 MB.
            write('''INSERT INTO radacct(acctsessionid,acctuniqueid,username,nasipaddress,acctstarttime,acctupdatetime,
                     acctstoptime,acctsessiontime,acctinputoctets,acctoutputoctets)
                     VALUES(%s,%s,%s,'3.3.3.1',NOW(),NOW(),NOW(),60,0,%s)''', ('T' + tag, uuid.uuid4().hex, names['used'], 70 * MB))
            self.assertIn(999999, rejects(names['used']), 'remaining data exceeded after import')

            Cases.job = job
            Cases.names = names

        def test_4_existing_empty_group_is_filled_once_and_reverted(self):
            write("UPDATE wisp_packages SET mikrotik_group='' WHERE name=%s", (profile,))
            write("DELETE FROM radgroupreply WHERE groupname=%s AND attribute='Mikrotik-Group'", (profile,))
            job = uuid.uuid4().hex
            result = execute_userman_import(payload({'unused': f'g_new_{tag}'}, group='hs-new'), operation_id=job)
            self.assertTrue(result['success'], result)
            self.assertEqual(rows('SELECT mikrotik_group g FROM wisp_packages WHERE name=%s', (profile,))[0]['g'], 'hs-new')
            self.assertEqual([r['value'] for r in rows("SELECT value FROM radgroupreply WHERE groupname=%s AND attribute='Mikrotik-Group'", (profile,))], ['hs-new'])
            again = execute_userman_import(payload({'unused': f'g_two_{tag}'}, group='hs-other'), operation_id=uuid.uuid4().hex)
            self.assertTrue(again['success'], again)
            self.assertEqual(rows('SELECT mikrotik_group g FROM wisp_packages WHERE name=%s', (profile,))[0]['g'], 'hs-new',
                             'a set group is never replaced')
            rollback_import(job)
            self.assertEqual(rows('SELECT COUNT(*) n FROM wisp_vouchers WHERE username=%s', (f'g_new_{tag}',))[0]['n'], 0)

        def test_5_restart_import_reverts_except_changed_accounts(self):
            rollback_import(Cases.job)
            # Unchanged accounts are reverted completely, baselines included.
            for kind in ('used_open', 'exhausted', 'unused'):
                name = Cases.names[kind]
                for table in ('wisp_vouchers', 'radcheck', 'wisp_session_baselines'):
                    self.assertEqual(rows(f'SELECT COUNT(*) n FROM {table} WHERE username=%s', (name,))[0]['n'], 0, (table, name))
            # The card that got new traffic after the import is kept for review (journal safety rule).
            used = Cases.names['used']
            self.assertEqual(rows('SELECT COUNT(*) n FROM wisp_vouchers WHERE username=%s', (used,))[0]['n'], 1)
            state = rows("SELECT state FROM wisp_userman_import_journal WHERE job_id=%s AND kind='account' AND identity_key=%s", (Cases.job, used))
            self.assertEqual(state[0]['state'], 'review_required')

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
