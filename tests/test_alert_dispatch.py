"""System alerts to Telegram/WhatsApp: filtering, repeat window, formatting,
delivery and the watchdog hook. Isolated: messaging APIs are stubbed."""
import ast
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services import alert_dispatch_service as alerts  # noqa: E402

CONFIG = dict(alerts.DEFAULTS)


class SettingsTests(unittest.TestCase):
    def test_phones(self):
        self.assertEqual(alerts.parse_phones('771234567, 00967 777 000 111\n0771234567،+967771234567'),
                         ['967771234567', '967777000111'])
        for bad in ('12', 'abc', ','.join(f'96777000000{i}' for i in range(6))):
            with self.assertRaises(ValueError):
                alerts.parse_phones(bad)
        self.assertEqual(alerts.parse_phones(''), [])

    def test_clean_settings(self):
        values = alerts.clean_settings({'alerts_enabled': 'on', 'alerts_min_severity': 'critical',
                                        'alerts_repeat_minutes': '15', 'alerts_whatsapp_phones': '771234567'})
        self.assertEqual(values, {'alerts_enabled': '1', 'alerts_telegram': '0', 'alerts_whatsapp_phones': '967771234567',
                                  'alerts_min_severity': 'critical', 'alerts_repeat_minutes': '15'})
        self.assertEqual(alerts.clean_settings({'alerts_min_severity': 'x', 'alerts_repeat_minutes': '30'})['alerts_min_severity'], 'warning')
        for minutes in ('0', '1441', 'x', ''):
            with self.assertRaises(ValueError):
                alerts.clean_settings({'alerts_repeat_minutes': minutes})


class DecisionTests(unittest.TestCase):
    def setUp(self):
        alerts._recent.clear()

    def test_threshold_recovery_and_disabled(self):
        self.assertFalse(alerts.should_send('ZOMBIE_SESSIONS_PURGED', 'info', True, CONFIG, now=0))
        self.assertFalse(alerts.should_send('CONTAINER_RESTART_PENDING', 'info', False, CONFIG, now=0))
        self.assertTrue(alerts.should_send('DISK_SPACE_CRITICAL', 'danger', False, CONFIG, now=0))
        self.assertTrue(alerts.should_send('DB_RECOVERY', 'info', True, CONFIG, now=0), 'recoveries always')
        self.assertFalse(alerts.should_send('DB_RECOVERY_X', 'info', False, CONFIG, now=0), 'not resolved')
        self.assertFalse(alerts.should_send('DB_DISCONNECT', 'critical', False, dict(CONFIG, alerts_enabled='0'), now=0))
        self.assertFalse(alerts.should_send('RADIUS_UNRESPONSIVE', 'danger', False,
                                            dict(CONFIG, alerts_min_severity='critical'), now=0))

    def test_repeat_window_and_escalation(self):
        self.assertTrue(alerts.should_send('LICENSE_OFFLINE_GRACE', 'warning', False, CONFIG, now=1000))
        self.assertFalse(alerts.should_send('LICENSE_OFFLINE_GRACE', 'warning', False, CONFIG, now=1000 + 60))
        self.assertTrue(alerts.should_send('LICENSE_OFFLINE_GRACE', 'critical', False, CONFIG, now=1000 + 120), 'higher severity')
        self.assertTrue(alerts.should_send('LICENSE_OFFLINE_GRACE', 'warning', False, CONFIG, now=1000 + 120 + 1801))

    def test_format(self):
        plain, rich = alerts.format_message('DB_DISCONNECT', 'critical', 'a <b> & c', False, 'شبكتي')
        self.assertTrue(plain.startswith('🔴 ALPHA RADIUS — شبكتي\na <b> & c'))
        self.assertIn('a &lt;b&gt; &amp; c', rich)
        self.assertTrue(alerts.format_message('DB_RECOVERY', 'info', 'ok', True)[0].startswith('✅'))


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.telegram = types.ModuleType('services.bot_notifications_service')
        self.telegram.get_notification_settings = lambda: {'settings': {'is_enabled': 1, 'bot_token': 't', 'chat_id': 'c'}}
        self.telegram.send_telegram_alert = Mock(return_value=(True, 'ok'))
        self.whatsapp = types.ModuleType('services.whatsapp_service')
        self.whatsapp.send_whatsapp_message = Mock(return_value=(False, 'gateway down'))
        self.modules = patch.dict(sys.modules, {'services.bot_notifications_service': self.telegram,
                                                'services.whatsapp_service': self.whatsapp})
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def test_both_channels_and_reported_failures(self):
        config = dict(CONFIG, alerts_whatsapp_phones='967771234567,967777000111')
        results = alerts.deliver('DB_DISCONNECT', 'plain', '<b>rich</b>', config)
        self.assertEqual([r[0] for r in results], ['telegram', 'whatsapp:967771234567', 'whatsapp:967777000111'])
        self.telegram.send_telegram_alert.assert_called_once_with('<b>rich</b>', message_type='DB_DISCONNECT')
        self.assertEqual(self.whatsapp.send_whatsapp_message.call_args.args, ('967777000111', 'plain'))
        self.assertEqual(self.whatsapp.send_whatsapp_message.call_args.kwargs, {'event_type': 'system_alert'})
        self.assertFalse(results[1][1])

    def test_disabled_bot_or_channel_is_skipped(self):
        self.telegram.get_notification_settings = lambda: {'settings': {'is_enabled': 0, 'bot_token': 't', 'chat_id': 'c'}}
        self.assertEqual(alerts.deliver('X', 'p', 'r', CONFIG), [])
        self.assertEqual(alerts.deliver('X', 'p', 'r', dict(CONFIG, alerts_telegram='0')), [])
        self.telegram.send_telegram_alert.assert_not_called()

    def test_notify_queues_and_worker_sends(self):
        alerts._recent.clear()
        with patch.object(alerts, 'settings', return_value=CONFIG), patch.object(alerts, '_network_name', return_value='N'), \
                patch.object(alerts, 'deliver') as deliver:
            self.assertTrue(alerts.notify_system_alert('RADIUS_UNRESPONSIVE', 'danger', 'down'))
            self.assertFalse(alerts.notify_system_alert('RADIUS_UNRESPONSIVE', 'danger', 'down'), 'repeat suppressed')
            alerts._queue.join()
        kind, plain, rich, config = deliver.call_args.args
        self.assertEqual(kind, 'RADIUS_UNRESPONSIVE')
        self.assertIn('N', plain)

    def test_whatsapp_copy_only_with_numbers(self):
        with patch.object(alerts, '_enqueue') as enqueue:
            with patch.object(alerts, 'settings', return_value=CONFIG):
                self.assertFalse(alerts.notify_whatsapp_copy('NAS_DOWN_ALERT', 'x'))
            with patch.object(alerts, 'settings', return_value=dict(CONFIG, alerts_whatsapp_phones='967771234567')):
                alerts.notify_whatsapp_copy('NAS_DOWN_ALERT', 'x')
        self.assertEqual(enqueue.call_args.args[3]['alerts_telegram'], '0', 'Telegram already has its own message')

    def test_settings_errors_never_raise(self):
        with patch.object(alerts, 'settings', side_effect=RuntimeError('db down')):
            self.assertFalse(alerts.notify_system_alert('DB_DISCONNECT', 'critical', 'x'))


class HookTests(unittest.TestCase):
    def test_watchdog_alert_is_forwarded_even_if_storing_failed(self):
        source = (ROOT / 'core/watchdog.py').read_text(encoding='utf-8')
        node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'log_system_alert')
        notify = Mock()
        stub = types.ModuleType('services.alert_dispatch_service')
        stub.notify_system_alert = notify
        ns = {'execute_write': Mock(side_effect=RuntimeError('db')), 'datetime': __import__('datetime')}
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'watchdog', 'exec'), ns)
        with patch.dict(sys.modules, {'services.alert_dispatch_service': stub}):
            ns['log_system_alert']('DB_DISCONNECT', 'critical', 'lost', resolved=False)
        notify.assert_called_once_with('DB_DISCONNECT', 'critical', 'lost', False)

    def test_wiring(self):
        nas = (ROOT / 'services/bot_notifications_service.py').read_text(encoding='utf-8')
        self.assertIn("notify_whatsapp_copy('NAS_DOWN_ALERT'", nas)
        self.assertIn("notify_whatsapp_copy('NAS_RECOVERED_ALERT'", nas)
        self.assertIn("'system_alerts_save': ['system.settings']", (ROOT / 'web/endpoint_permissions.py').read_text(encoding='utf-8'))
        from jinja2 import Environment, FileSystemLoader
        Environment(loader=FileSystemLoader(str(ROOT / 'web/templates'))).parse(
            (ROOT / 'web/templates/notifications_center.html').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
