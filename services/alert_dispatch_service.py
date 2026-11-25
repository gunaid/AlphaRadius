"""Send system alerts to the operator over Telegram and/or WhatsApp.

Every system alert passes through core.watchdog.log_system_alert (database or
RADIUS down, low disk, container health, license offline stages and license
non-compliance, recoveries). After it is stored, notify_system_alert() decides
and queues the message; a single background thread sends it, so a slow or
unreachable messaging API never blocks the watchdog.

Rules (settings in wisp_system_settings, page: Notifications center):
* alerts_enabled (default 1);
* alerts_min_severity: info < warning < danger < critical (default warning);
* recoveries (resolved alerts named *RECOVERY / *RECOVERED) are always sent,
  so an outage alert is followed by its "back to normal";
* the same alert type is not repeated within alerts_repeat_minutes
  (default 30) unless its severity rises;
* Telegram uses the existing bot/chat of the notifications center when
  alerts_telegram = 1 and the bot is enabled;
* WhatsApp goes to every number in alerts_whatsapp_phones through the
  configured gateway (license feature whatsapp_gateway).
No SMS provider is involved.
"""
import datetime
import html
import logging
import queue
import threading
import time

logger = logging.getLogger(__name__)

LEVELS = {'info': 0, 'warning': 1, 'danger': 2, 'critical': 3}
ICONS = {'info': 'ℹ️', 'warning': '🟡', 'danger': '🟠', 'critical': '🔴'}
DEFAULTS = {'alerts_enabled': '1', 'alerts_telegram': '1', 'alerts_whatsapp_phones': '',
            'alerts_min_severity': 'warning', 'alerts_repeat_minutes': '30'}
MAX_PHONES = 5

_queue = queue.Queue(maxsize=200)
_recent = {}
_recent_lock = threading.Lock()
_worker = None
_worker_lock = threading.Lock()


# ---------------------------------------------------------------- settings

def settings():
    from database.db import query_all
    values = dict(DEFAULTS)
    try:
        keys = tuple(DEFAULTS)
        rows = query_all('SELECT `key`, `value` FROM wisp_system_settings WHERE `key` IN (%s)'
                         % ','.join('?' for _ in keys), keys)
        values.update({r['key']: str(r['value'] or '') for r in rows})
    except Exception:
        pass
    return values


def clean_phone(raw):
    """Same digits rule as whatsapp_service.clean_phone_number, plus a Yemeni
    mobile typed without country code (7XXXXXXXX) -> 9677XXXXXXXX."""
    import re
    digits = re.sub(r'\D', '', str(raw or ''))
    if digits.startswith('00'):
        digits = digits[2:]
    if digits.startswith('0') and len(digits) == 10:
        digits = '967' + digits[1:]
    if len(digits) == 9 and digits.startswith('7'):
        digits = '967' + digits
    return digits


def parse_phones(raw):
    phones = []
    for part in str(raw or '').replace('،', ',').replace('\n', ',').split(','):
        part = part.strip()
        if not part:
            continue
        phone = clean_phone(part)
        if not phone or not phone.isdigit() or not 8 <= len(phone) <= 15:
            raise ValueError(f'رقم واتساب غير صالح: {part}')
        if phone not in phones:
            phones.append(phone)
    if len(phones) > MAX_PHONES:
        raise ValueError(f'الحد الأقصى {MAX_PHONES} أرقام واتساب للتنبيهات.')
    return phones


def clean_settings(form):
    severity = form.get('alerts_min_severity') if form.get('alerts_min_severity') in LEVELS else 'warning'
    minutes = str(form.get('alerts_repeat_minutes') or '').strip()
    if not minutes.isdigit() or not 1 <= int(minutes) <= 1440:
        raise ValueError('مدة منع التكرار يجب أن تكون من 1 إلى 1440 دقيقة.')
    return {'alerts_enabled': '1' if form.get('alerts_enabled') in ('1', 'on') else '0',
            'alerts_telegram': '1' if form.get('alerts_telegram') in ('1', 'on') else '0',
            'alerts_whatsapp_phones': ','.join(parse_phones(form.get('alerts_whatsapp_phones'))),
            'alerts_min_severity': severity, 'alerts_repeat_minutes': str(int(minutes))}


def save_settings(form):
    from database.db import execute_update, execute_write, query_one
    values = clean_settings(form)
    for key, value in values.items():
        if query_one('SELECT `key` FROM wisp_system_settings WHERE `key` = ?', (key,)):
            execute_update('UPDATE wisp_system_settings SET `value` = ? WHERE `key` = ?', (value, key))
        else:
            execute_write('INSERT INTO wisp_system_settings (`key`, `value`, `description`) VALUES (?, ?, ?)',
                          (key, value, 'تنبيهات النظام عبر Telegram/WhatsApp'))
    return values


# ---------------------------------------------------------------- decision

def is_recovery(alert_type, resolved):
    return bool(resolved) and str(alert_type).upper().endswith(('RECOVERY', 'RECOVERED'))


def should_send(alert_type, severity, resolved, config, now=None):
    """Apply the enabled flag, severity threshold and repeat window."""
    if config.get('alerts_enabled') != '1':
        return False
    level = LEVELS.get(severity, 1)
    if not is_recovery(alert_type, resolved) and level < LEVELS.get(config.get('alerts_min_severity'), 1):
        return False
    now = time.time() if now is None else now
    window = int(config.get('alerts_repeat_minutes') or 30) * 60
    with _recent_lock:
        last = _recent.get(alert_type)
        if last and now - last[0] < window and level <= last[1]:
            return False
        _recent[alert_type] = (now, level)
    return True


def format_message(alert_type, severity, message, resolved, network='', at=None):
    at = at or datetime.datetime.now()
    icon = '✅' if is_recovery(alert_type, resolved) else ICONS.get(severity, '🔔')
    title = f'{icon} ALPHA RADIUS' + (f' — {network}' if network else '')
    plain = f"{title}\n{message}\nالنوع: {alert_type}\nالوقت: {at:%Y-%m-%d %H:%M}"
    rich = (f"<b>{html.escape(title)}</b>\n{html.escape(message)}\n"
            f"<code>{html.escape(alert_type)}</code> · {at:%Y-%m-%d %H:%M}")
    return plain, rich


# ---------------------------------------------------------------- sending

def _network_name():
    from database.db import query_one
    try:
        row = query_one("SELECT `value` FROM wisp_system_settings WHERE `key` = 'network_name'")
        return (row or {}).get('value') or ''
    except Exception:
        return ''


def deliver(kind, plain, rich, config):
    """Send now (worker thread); returns a list of (channel, ok, detail)."""
    results = []
    if config.get('alerts_telegram') == '1':
        try:
            from services.bot_notifications_service import get_notification_settings, send_telegram_alert
            channel = (get_notification_settings().get('settings') or {})
            if channel.get('is_enabled') and channel.get('bot_token') and channel.get('chat_id'):
                ok, detail = send_telegram_alert(rich, message_type=kind)
                results.append(('telegram', ok, detail))
        except Exception as exc:
            results.append(('telegram', False, type(exc).__name__))
    phones = [p for p in str(config.get('alerts_whatsapp_phones') or '').split(',') if p]
    if phones:
        from services.whatsapp_service import send_whatsapp_message
        for phone in phones:
            try:
                ok, detail = send_whatsapp_message(phone, plain, event_type='system_alert')
            except Exception as exc:
                ok, detail = False, type(exc).__name__
            results.append(('whatsapp:' + phone, ok, detail))
    for channel, ok, detail in results:
        if not ok:
            logger.warning('System alert %s not delivered via %s: %s', kind, channel, str(detail)[:200])
    return results


def _loop():
    while True:
        item = _queue.get()
        try:
            deliver(*item)
        except Exception:
            logger.exception('System alert delivery failed')
        finally:
            _queue.task_done()


def _enqueue(kind, plain, rich, config):
    global _worker
    with _worker_lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_loop, name='SystemAlertSender', daemon=True)
            _worker.start()
    try:
        _queue.put_nowait((kind, plain, rich, config))
        return True
    except queue.Full:
        logger.warning('System alert queue full; dropped %s', kind)
        return False


def notify_system_alert(alert_type, severity, message, resolved=False):
    """Called after a system alert is stored. Never raises."""
    try:
        config = settings()
        if not should_send(alert_type, severity, resolved, config):
            return False
        plain, rich = format_message(alert_type, severity, message, resolved, _network_name())
        return _enqueue(alert_type, plain, rich, config)
    except Exception:
        logger.exception('System alert notification failed')
        return False


def notify_whatsapp_copy(kind, plain):
    """WhatsApp copy of an event that already has its own Telegram message (router down/up)."""
    try:
        config = settings()
        if config.get('alerts_enabled') != '1' or not config.get('alerts_whatsapp_phones'):
            return False
        return _enqueue(kind, plain, '', dict(config, alerts_telegram='0'))
    except Exception:
        logger.exception('WhatsApp alert copy failed')
        return False


def send_test(config=None):
    """Synchronous test from the settings page."""
    config = config or settings()
    plain, rich = format_message('ALERT_TEST', 'warning', 'رسالة تجربة لتنبيهات النظام.', False, _network_name())
    return deliver('ALERT_TEST', plain, rich, config)
