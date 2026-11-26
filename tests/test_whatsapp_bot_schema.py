"""WhatsApp bot, message log and broadcast against the real table shapes.

The service used columns and a table that the schema does not have:
- wisp_whatsapp_logs stores recipient_phone / entity_type, direction as
  enum('inbound','outbound') and a status enum without 'received';
- there is no wisp_whatsapp_sessions table (bot state now lives in memory);
- wisp_subscribers has status, not is_active;
- reseller wallets live on wisp_managers (wallet_balance), not wisp_resellers.

Isolated: SQLite tables with the same columns, and CHECK constraints standing
in for the MariaDB enums (strict mode rejects out-of-enum values).
"""
import re
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.test_whatsapp_templates import Database, load_service  # noqa: E402

EXTRA_SCHEMA = """
CREATE TABLE wisp_whatsapp_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, recipient_phone TEXT NOT NULL, message_type TEXT DEFAULT 'text',
    direction TEXT DEFAULT 'outbound' CHECK (direction IN ('inbound','outbound')), message_body TEXT NOT NULL,
    status TEXT DEFAULT 'sent' CHECK (status IN ('pending','sent','delivered','read','failed')),
    error_message TEXT, entity_type TEXT, entity_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE wisp_packages (id INTEGER PRIMARY KEY, name TEXT, price REAL, volume_quota_mb INTEGER, validity_value INTEGER,
    validity_unit TEXT, rate_download TEXT, rate_upload TEXT, is_active INTEGER DEFAULT 1);
CREATE TABLE wisp_vouchers (id INTEGER PRIMARY KEY, username TEXT, pin_code TEXT, serial_number TEXT, package_id INTEGER,
    status TEXT, first_used_at TEXT, last_renewed_at TEXT, expires_at TEXT, snap_volume_quota_mb INTEGER, extra_quota_mb INTEGER);
CREATE TABLE wisp_subscribers (id INTEGER PRIMARY KEY, username TEXT, full_name TEXT, phone TEXT, status TEXT DEFAULT 'active',
    package_id INTEGER, extra_quota_mb INTEGER, last_renewed_at TEXT, created_at TEXT, expires_at TEXT);
CREATE TABLE radacct (username TEXT, acctinputoctets INTEGER, acctoutputoctets INTEGER, acctsessiontime INTEGER,
    acctstarttime TEXT, acctupdatetime TEXT);
CREATE TABLE wisp_managers (id INTEGER PRIMARY KEY, username TEXT, full_name TEXT, phone TEXT, wallet_balance REAL,
    commission_percent REAL, is_active INTEGER DEFAULT 1, is_deleted INTEGER DEFAULT 0);
CREATE TABLE wisp_resellers (id INTEGER PRIMARY KEY, name TEXT, phone TEXT);
INSERT INTO wisp_packages VALUES (1, 'Daily', 100, 1024, 1, 'days', '0', '0', 1);
INSERT INTO wisp_vouchers (id, username, pin_code, serial_number, package_id, status) VALUES (1, 'CARD1234', 'CARD1234', 'S1', 1, 'unused');
INSERT INTO wisp_subscribers (id, username, full_name, phone, status, package_id) VALUES
    (1, 'sub-active', 'Active One', '967700000011', 'active', 1),
    (2, 'sub-active2', 'Active Two', '967700000012', 'active', 1),
    (3, 'sub-expired', 'Expired', '967700000013', 'expired', 1);
INSERT INTO wisp_managers VALUES (1, 'agent', 'Agent One', '967700000021', 2500, 7.5, 1, 0),
                                 (2, 'gone', 'Deleted Agent', '967700000022', 900, 5, 1, 1);
"""

PHONE = '967700000001'


class BotTests(unittest.TestCase):
    def setUp(self):
        self.db = Database()
        self.db.conn.executescript(EXTRA_SCHEMA)
        self.service = load_service(self.db)
        # send_whatsapp_message imports the license check at call time.
        policy = types.SimpleNamespace(guarded=lambda feature: (lambda fn: fn), enabled=lambda feature: True)
        patcher = patch.dict(sys.modules, {'core.license_feature_policy': policy})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_conversation_state_survives_between_messages(self):
        first = self.service.process_incoming_whatsapp_message(PHONE, '1', 'Tester')
        self.assertIn('يرجى إرسال اسم المستخدم', first)
        second = self.service.process_incoming_whatsapp_message(PHONE, 'CARD1234', 'Tester')
        self.assertIn('CARD1234', second)
        self.assertIn('تفاصيل كارت الإنترنت', second)
        third = self.service.process_incoming_whatsapp_message(PHONE, 'hello', 'Tester')   # back to idle: welcome
        self.assertIn('ALPHA RADIUS', third)

    def test_session_expires_after_inactivity(self):
        clock = [1000.0]
        with patch.object(self.service.time, 'monotonic', lambda: clock[0]):
            self.service.process_incoming_whatsapp_message(PHONE, '1')
            clock[0] += self.service._SESSION_TTL_SECONDS + 1
            reply = self.service.process_incoming_whatsapp_message(PHONE, 'CARD1234')
        self.assertNotIn('تفاصيل كارت الإنترنت', reply)   # the old "awaiting card" state was dropped
        self.assertEqual(len(self.service._sessions), 1)

    def test_log_rows_use_real_columns_and_enums(self):
        self.service.process_incoming_whatsapp_message(PHONE, '1')
        ok, _ = self.service.send_whatsapp_message(PHONE, 'reply text', event_type='bot_reply')
        self.assertTrue(ok)
        stored = self.db.conn.execute('SELECT direction, recipient_phone, status, entity_type FROM wisp_whatsapp_logs ORDER BY id').fetchall()
        self.assertEqual([tuple(r) for r in stored], [('inbound', PHONE, 'delivered', 'incoming_command'),
                                                      ('outbound', PHONE, 'sent', 'bot_reply')])
        logs = self.service.get_whatsapp_logs()
        self.assertEqual([(l['direction'], l['status'], l['phone_number'], l['event_type']) for l in logs],
                         [('out', 'sent', PHONE, 'bot_reply'), ('in', 'received', PHONE, 'incoming_command')])
        self.assertEqual([l['direction'] for l in self.service.get_whatsapp_logs(filter_status='received')], ['in'])
        self.assertEqual([l['direction'] for l in self.service.get_whatsapp_logs(filter_status='sent')], ['out'])
        self.assertEqual(len(self.service.get_whatsapp_logs(filter_phone='0000001')), 2)
        self.assertEqual(self.service.get_whatsapp_logs(filter_phone='999'), [])
        summary = {r['status']: r['cnt'] for r in self.db.query_all(self.service.LOG_STATUS_SUMMARY_SQL)}
        self.assertEqual(summary, {'received': 1, 'sent': 1})

    def test_reseller_wallet_comes_from_managers(self):
        reply = self.service.process_incoming_whatsapp_message('967700000021', 'محفظتي')
        self.assertIn('Agent One', reply)
        self.assertIn('2500', reply)
        self.assertIn('7.5%', reply)
        for word in ('وكيل', 'رصيد المحفظة'):
            self.assertIn('Agent One', self.service.process_incoming_whatsapp_message('967700000021', word))
        deleted = self.service.process_incoming_whatsapp_message('967700000022', 'محفظتي')
        self.assertNotIn('Deleted Agent', deleted)

    def test_subscriber_status_and_active_broadcast(self):
        self.assertEqual(self.service.query_subscriber_status('sub-active')['status'], 'نشط')
        self.assertEqual(self.service.query_subscriber_status('sub-expired')['status'], 'منتهي')

        class NoThread:
            def __init__(self, *args, **kwargs):
                pass

            def start(self):
                pass

        fake_threading = types.SimpleNamespace(Thread=NoThread, Lock=self.service.threading.Lock)
        with patch.object(self.service, 'threading', fake_threading):
            active, _, _ = self.service.send_broadcast_campaign('active_subscribers', 'hello')
            everyone, _, _ = self.service.send_broadcast_campaign('all_subscribers', 'hello')
        self.assertEqual((active, everyone), (2, 3))


class SchemaAgreementTests(unittest.TestCase):
    def test_log_table_columns_match_the_service(self):
        expected = {'id', 'recipient_phone', 'message_type', 'direction', 'message_body', 'status',
                    'error_message', 'entity_type', 'entity_id', 'created_at'}
        for name, start, end in (('database/schema_mysql.sql', 'CREATE TABLE `wisp_whatsapp_logs`', ') ENGINE'),
                                 ('database/schema_healer.py', 'CREATE TABLE IF NOT EXISTS wisp_whatsapp_logs', '"""')):
            text = (ROOT / name).read_text(encoding='utf-8')
            block = text[text.index(start):]
            block = block[:block.index(end)]
            columns = {m.group(1) for m in re.finditer(
                r'^\s*`?(\w+)`?\s+(?:int|bigint|varchar|text|enum|datetime)\b', block, re.M | re.I)}
            self.assertEqual(columns, expected, name)

    def test_service_uses_no_missing_tables_or_columns(self):
        service = (ROOT / 'services/whatsapp_service.py').read_text(encoding='utf-8')
        self.assertNotIn('wisp_whatsapp_sessions', service)
        self.assertNotIn('FROM wisp_resellers WHERE phone = ?', service)
        self.assertNotIn("AND is_active = 1\"", service)
        self.assertNotIn('phone_number LIKE', service)


if __name__ == '__main__':
    unittest.main()
