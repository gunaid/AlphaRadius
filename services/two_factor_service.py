"""Optional second factor for panel managers, asked only on a new device.

A manager may enable an authenticator app (TOTP, RFC 6238: SHA-1, 30 s,
6 digits, one step of clock drift either way). With it enabled, a password
login from a browser that is not yet trusted asks for the 6-digit code; the
browser then gets a random device token (cookie, stored only as SHA-256) and
is not asked again for TRUST_DAYS. No SMS or e-mail is needed.

A code is accepted once: its time step must be newer than the last accepted
step. A pending login expires after PENDING_SECONDS or MAX_ATTEMPTS wrong codes.
"""
import base64
import datetime
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
STEP = 30
DRIFT_STEPS = 1
TRUST_DAYS = 90
PENDING_SECONDS = 300
MAX_ATTEMPTS = 5
DEVICE_COOKIE = 'alpha_device'
ISSUER = 'ALPHA RADIUS'

TOTP_SQL = """CREATE TABLE IF NOT EXISTS wisp_manager_totp (
 manager_id INT NOT NULL PRIMARY KEY,
 secret_b32 VARCHAR(64) NOT NULL,
 enabled TINYINT NOT NULL DEFAULT 0,
 last_step BIGINT NOT NULL DEFAULT 0,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""

DEVICES_SQL = """CREATE TABLE IF NOT EXISTS wisp_manager_devices (
 id BIGINT AUTO_INCREMENT PRIMARY KEY,
 manager_id INT NOT NULL,
 token_hash CHAR(64) NOT NULL,
 label VARCHAR(120) NOT NULL DEFAULT '',
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_seen_at DATETIME NULL,
 expires_at DATETIME NOT NULL,
 UNIQUE KEY uq_manager_device (token_hash),
 KEY idx_manager_devices (manager_id, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""


# ------------------------------------------------------------------ TOTP

def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


def _key(secret_b32):
    text = str(secret_b32 or '').strip().replace(' ', '').upper()
    return base64.b32decode(text + '=' * (-len(text) % 8))


def code_at(secret_b32, step):
    digest = hmac.new(_key(secret_b32), struct.pack('>Q', int(step)), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def matching_step(secret_b32, code, now=None, last_step=0):
    """The accepted time step for this code, or None (wrong, reused or malformed)."""
    code = str(code or '').strip().replace(' ', '')
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = int((time.time() if now is None else now) // STEP)
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        if step > int(last_step or 0) and hmac.compare_digest(code_at(secret_b32, step), code):
            return step
    return None


def provisioning_uri(secret_b32, username):
    label = quote(f'{ISSUER}:{username}')
    return f'otpauth://totp/{label}?secret={secret_b32}&issuer={quote(ISSUER)}&digits={DIGITS}&period={STEP}'


def token_hash(token):
    return hashlib.sha256(str(token or '').encode('utf-8')).hexdigest()


# ------------------------------------------------------------- storage

def ensure_tables():
    from database.db import execute_write, get_connection, is_mysql_conn
    conn = get_connection()
    try:
        mysql = is_mysql_conn(conn)
    finally:
        conn.close()
    if mysql:
        execute_write(TOTP_SQL)
        execute_write(DEVICES_SQL)
    else:
        execute_write(TOTP_SQL.split(') ENGINE')[0] + ')')
        execute_write(DEVICES_SQL.replace('BIGINT AUTO_INCREMENT PRIMARY KEY', 'INTEGER PRIMARY KEY AUTOINCREMENT')
                      .replace(',\n UNIQUE KEY uq_manager_device (token_hash),\n KEY idx_manager_devices (manager_id, expires_at)', '')
                      .split(') ENGINE')[0] + ')')


def totp_record(manager_id):
    from database.db import query_one
    try:
        return query_one('SELECT * FROM wisp_manager_totp WHERE manager_id = ?', (int(manager_id),))
    except Exception:
        return None


def is_enabled(manager_id):
    row = totp_record(manager_id)
    return bool(row and int(row.get('enabled') or 0))


def start_setup(manager_id):
    """Create (or replace a not yet enabled) secret; returns it."""
    from database.db import execute_write, execute_update
    row = totp_record(manager_id)
    if row and int(row.get('enabled') or 0):
        raise ValueError('التحقق بخطوتين مفعّل بالفعل؛ أوقفه أولًا لإنشاء مفتاح جديد.')
    secret = new_secret()
    if row:
        execute_update('UPDATE wisp_manager_totp SET secret_b32 = ?, last_step = 0 WHERE manager_id = ?', (secret, int(manager_id)))
    else:
        execute_write('INSERT INTO wisp_manager_totp (manager_id, secret_b32, enabled, last_step) VALUES (?, ?, 0, 0)',
                      (int(manager_id), secret))
    return secret


def verify_code(manager_id, code, now=None, require_enabled=True):
    """Check and consume a code atomically (the step only moves forward)."""
    from database.db import execute_update
    row = totp_record(manager_id)
    if not row or (require_enabled and not int(row.get('enabled') or 0)):
        return False
    step = matching_step(row['secret_b32'], code, now, row.get('last_step') or 0)
    if step is None:
        return False
    return execute_update('UPDATE wisp_manager_totp SET last_step = ? WHERE manager_id = ? AND last_step < ?',
                          (step, int(manager_id), step)) == 1


def enable(manager_id, code, now=None):
    from database.db import execute_update
    if not verify_code(manager_id, code, now, require_enabled=False):
        raise ValueError('الرمز غير صحيح؛ تأكد من ساعة الهاتف وأعد المحاولة.')
    execute_update('UPDATE wisp_manager_totp SET enabled = 1 WHERE manager_id = ?', (int(manager_id),))


def disable(manager_id):
    """Turn the second factor off and forget every trusted device of the manager."""
    from database.db import execute_update
    execute_update('DELETE FROM wisp_manager_totp WHERE manager_id = ?', (int(manager_id),))
    execute_update('DELETE FROM wisp_manager_devices WHERE manager_id = ?', (int(manager_id),))


# ------------------------------------------------------------- devices

def is_trusted_device(manager_id, cookie_value):
    from database.db import query_one, execute_update
    if not cookie_value:
        return False
    row = query_one('SELECT id FROM wisp_manager_devices WHERE manager_id = ? AND token_hash = ? AND expires_at > ?',
                    (int(manager_id), token_hash(cookie_value), _now()))
    if row:
        execute_update('UPDATE wisp_manager_devices SET last_seen_at = ? WHERE id = ?', (_now(), row['id']))
    return bool(row)


def trust_device(manager_id, user_agent=''):
    """Register this browser; returns the raw token for the cookie."""
    from database.db import execute_write
    token = secrets.token_urlsafe(32)
    expires = datetime.datetime.now() + datetime.timedelta(days=TRUST_DAYS)
    execute_write('INSERT INTO wisp_manager_devices (manager_id, token_hash, label, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?)',
                  (int(manager_id), token_hash(token), str(user_agent or '')[:120], _now(),
                   expires.strftime('%Y-%m-%d %H:%M:%S')))
    return token


def devices(manager_id):
    from database.db import query_all
    try:
        return query_all('''SELECT id, label, created_at, last_seen_at, expires_at FROM wisp_manager_devices
                            WHERE manager_id = ? AND expires_at > ? ORDER BY last_seen_at DESC''', (int(manager_id), _now()))
    except Exception:
        return []


def forget_devices(manager_id):
    from database.db import execute_update
    return execute_update('DELETE FROM wisp_manager_devices WHERE manager_id = ?', (int(manager_id),))


def _now():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


# ------------------------------------------------------- pending login

def needs_second_factor(manager_id, cookie_value):
    try:
        return is_enabled(manager_id) and not is_trusted_device(manager_id, cookie_value)
    except Exception:
        # Missing tables (first start) mean nobody has enabled it yet.
        return False


def pending_valid(pending, now=None):
    now = time.time() if now is None else now
    return (isinstance(pending, dict) and isinstance(pending.get('manager_id'), int)
            and now - float(pending.get('at') or 0) <= PENDING_SECONDS
            and int(pending.get('attempts') or 0) < MAX_ATTEMPTS)
