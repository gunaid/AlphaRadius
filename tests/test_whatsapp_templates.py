"""WhatsApp templates use the real wisp_whatsapp_templates columns.

The table stores template_key / message_body / is_active (schema_mysql.sql and
schema_healer.py). whatsapp_service used event_key / template_text /
is_enabled, so every lookup raised "Unknown column 'event_key'", ran the schema
healer twice per message and broke the bot's default reply.

Isolated: services.whatsapp_service runs against an in-memory SQLite table with
the same columns; database.db, core.config and the license policy are stubbed.
"""
import importlib
import re
import sqlite3
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TEMPLATE_COLUMNS = {'id', 'template_key', 'title', 'category', 'message_body', 'is_active', 'variables_hint', 'updated_at'}

SQLITE_SCHEMA = """
CREATE TABLE wisp_whatsapp_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, gateway_provider TEXT, api_endpoint TEXT, instance_name TEXT,
    is_bot_enabled INTEGER, is_notifications_enabled INTEGER, status TEXT);
CREATE TABLE wisp_whatsapp_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT, template_key TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
    category TEXT DEFAULT 'notification', message_body TEXT NOT NULL, is_active INTEGER DEFAULT 1,
    variables_hint TEXT DEFAULT '', updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
"""


class Database:
    def __init__(self):
        self.conn = sqlite3.connect(':memory:', check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SQLITE_SCHEMA)
        self.statements = []

    def _run(self, sql, params=()):
        self.statements.append(sql)
        return self.conn.execute(sql, params)

    # database.db returns dict rows (callers use .get); match that.
    def query_one(self, sql, params=()):
        row = self._run(sql, params).fetchone()
        return dict(row) if row is not None else None

    def query_all(self, sql, params=()):
        return [dict(row) for row in self._run(sql, params).fetchall()]

    def execute_write(self, sql, params=()):
        self._run(sql, params)
        self.conn.commit()

    execute_update = execute_write


def load_service(db):
    stubs = {
        'database.db': types.SimpleNamespace(query_one=db.query_one, query_all=db.query_all,
                                             execute_write=db.execute_write, execute_update=db.execute_update),
        'core.config': types.SimpleNamespace(APP_NAME='ALPHA RADIUS', APP_VERSION='test'),
        'core.time_service': types.SimpleNamespace(get_system_now=lambda: None, get_system_now_str=lambda: ''),
        'core.license_feature_policy': types.SimpleNamespace(guarded=lambda feature: (lambda fn: fn),
                                                             enabled=lambda feature: True),
    }
    patcher = patch.dict(sys.modules, stubs)
    patcher.start()
    sys.modules.pop('services.whatsapp_service', None)
    try:
        module = importlib.import_module('services.whatsapp_service')
    finally:
        sys.modules.pop('services.whatsapp_service', None)
        patcher.stop()
    return module


class TemplateColumnsTests(unittest.TestCase):
    def setUp(self):
        self.db = Database()
        self.service = load_service(self.db)

    def test_seed_and_read_use_real_columns(self):
        templates = self.service.get_all_templates()
        keys = [t['event_key'] for t in templates]
        self.assertEqual(keys, [t['event_key'] for t in self.service.DEFAULT_TEMPLATES])
        welcome = self.service.get_template_by_key('welcome_menu')
        self.assertIn('{network_name}', welcome['template_text'])
        self.assertEqual(welcome['is_enabled'], 1)
        stored = self.db.conn.execute("SELECT message_body FROM wisp_whatsapp_templates WHERE template_key='welcome_menu'").fetchone()
        self.assertEqual(stored[0], welcome['template_text'])
        self.assertIsNone(self.service.get_template_by_key('missing'))

    def test_save_template_updates_message_body_and_is_active(self):
        template = self.service.get_template_by_key('voucher_issued')
        self.service.save_template(template['id'], 'new title', 'new body {username}', 0)
        saved = self.service.get_template_by_key('voucher_issued')
        self.assertEqual((saved['title'], saved['template_text'], saved['is_enabled']), ('new title', 'new body {username}', 0))

    def test_seeding_runs_once_and_keeps_edits(self):
        self.service.get_all_templates()
        template = self.service.get_template_by_key('quota_warning')
        self.service.save_template(template['id'], template['title'], 'edited', 1)
        before = len(self.db.statements)
        for _ in range(5):
            self.service.get_template_by_key('quota_warning')
            self.service.get_all_templates()
        self.assertEqual(len(self.db.statements) - before, 10)   # only the reads, no seeding queries
        self.assertEqual(self.service.get_template_by_key('quota_warning')['template_text'], 'edited')
        count = self.db.conn.execute('SELECT COUNT(*) FROM wisp_whatsapp_templates').fetchone()[0]
        self.assertEqual(count, len(self.service.DEFAULT_TEMPLATES))

    def test_failed_seed_is_not_retried_on_every_call(self):
        self.db.conn.execute('DROP TABLE wisp_whatsapp_settings')
        with self.assertLogs('whatsapp_service', 'WARNING'):
            self.service.seed_default_whatsapp_data()
        before = len(self.db.statements)
        self.service.seed_default_whatsapp_data()
        self.assertEqual(len(self.db.statements), before)


class SchemaAgreementTests(unittest.TestCase):
    def test_mysql_schema_and_healer_define_the_columns_the_service_uses(self):
        for name, start, end in (('database/schema_mysql.sql', 'CREATE TABLE `wisp_whatsapp_templates`', ') ENGINE'),
                                 ('database/schema_healer.py', 'CREATE TABLE IF NOT EXISTS wisp_whatsapp_templates', '"""')):
            text = (ROOT / name).read_text(encoding='utf-8')
            block = text[text.index(start):]
            block = block[:block.index(end)]
            columns = {m.group(1) for m in re.finditer(r'^\s*`?(\w+)`?\s+(?:int|varchar|text|tinyint|datetime)\b',
                                                        block, re.M | re.I)}
            self.assertEqual(columns, TEMPLATE_COLUMNS, name)


if __name__ == '__main__':
    unittest.main()
