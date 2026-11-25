"""Cloned MACs: list, detection report and router profile sync (RouterOS 6 and 7).

See database/cloned_mac_schema.py for the RADIUS side. This module:

* keeps the list of cloned MACs (manual, or added from the detection report);
* builds a detection report from accounting: one MAC seen with several cards,
  on several ports/VLANs, open more than once at the same time, or with many
  very short sessions;
* syncs each router over its API: for every hotspot user profile P it makes
  sure ``P-nocookie`` exists with the same settings and add-mac-cookie=no,
  records which copies exist (wisp_cloned_mac_profiles; RADIUS uses only
  those), and removes existing MAC cookies of listed MACs.

Only the fields both RouterOS 6 and 7 accept are copied, and only those the
source profile actually has. If the router refuses the full copy, a minimal
copy is tried; if that fails too, nothing is recorded for that profile and
RADIUS keeps sending the original profile.
"""
import logging
import time

from database.cloned_mac_schema import PROFILE_SUFFIX

logger = logging.getLogger(__name__)

SYNC_INTERVAL_SECONDS = 900
CHECK_INTERVAL_SECONDS = 60
COPY_FIELDS = ('address-pool', 'idle-timeout', 'keepalive-timeout', 'status-autorefresh', 'shared-users',
               'rate-limit', 'session-timeout', 'address-list', 'incoming-filter', 'outgoing-filter',
               'incoming-packet-mark', 'outgoing-packet-mark', 'open-status-page', 'transparent-proxy',
               'on-login', 'on-logout', 'advertise', 'advertise-url', 'advertise-interval',
               'advertise-timeout', 'advertise-intervals', 'insert-queue-before', 'parent-queue', 'queue-type',
               'mac-cookie-timeout')
MINIMAL_FIELDS = ('shared-users', 'idle-timeout', 'keepalive-timeout', 'on-login', 'on-logout', 'address-list')
DETECT_DEFAULTS = dict(days=7, min_cards=3, min_ports=2, min_short=20, short_seconds=60, limit=200)

_last_sync = 0.0
_last_check = 0.0


def normalize(mac):
    from core.mac_policy import normalize_mac
    return normalize_mac(mac)


# ---------------------------------------------------------------- the list

def list_macs():
    from database.db import query_all
    return query_all('SELECT mac,note,source,created_by,created_at FROM wisp_cloned_macs ORDER BY created_at DESC')


def add_mac(mac, note='', created_by='', source='manual'):
    from database.db import execute_write, query_one
    mac = normalize(mac)
    note = ' '.join(str(note or '').split())[:250]
    if query_one('SELECT mac FROM wisp_cloned_macs WHERE mac=?', (mac,)):
        return mac, False
    execute_write('INSERT INTO wisp_cloned_macs(mac,note,source,created_by,created_at) VALUES (?,?,?,?,NOW())',
                  (mac, note, source if source in ('manual', 'detected', 'preset') else 'manual', str(created_by or '')[:64]))
    return mac, True


def remove_mac(mac):
    from database.db import execute_update
    return execute_update('DELETE FROM wisp_cloned_macs WHERE mac=?', (normalize(mac),)) > 0


def enabled():
    from database.db import query_one
    row = query_one("SELECT `value` FROM wisp_system_settings WHERE `key`='cloned_mac_enabled'")
    return bool(row and str(row.get('value')) == '1')


def set_enabled(value):
    from database.db import execute_update, execute_write
    flag = '1' if value else '0'
    if not execute_update("UPDATE wisp_system_settings SET `value`=? WHERE `key`='cloned_mac_enabled'", (flag,)):
        from database.db import query_one
        if not query_one("SELECT `key` FROM wisp_system_settings WHERE `key`='cloned_mac_enabled'"):
            execute_write("INSERT INTO wisp_system_settings(`key`,`value`,`description`) VALUES ('cloned_mac_enabled',?,?)",
                          (flag, 'تعطيل كوكي الماك للماكات المستنسخة'))
    return flag == '1'


# ---------------------------------------------------------- detection

def detection_params(args):
    def number(key, low, high):
        try:
            value = int(str(args.get(key, '')).strip())
        except (TypeError, ValueError):
            return DETECT_DEFAULTS[key]
        return min(high, max(low, value))
    return dict(days=number('days', 1, 90), min_cards=number('min_cards', 2, 1000),
                min_ports=number('min_ports', 2, 1000), min_short=number('min_short', 5, 100000),
                short_seconds=DETECT_DEFAULTS['short_seconds'], limit=DETECT_DEFAULTS['limit'])


def detect(params=None):
    """Suspected cloned MACs from accounting in the last N days."""
    from database.db import query_all
    p = dict(DETECT_DEFAULTS, **(params or {}))
    rows = query_all("""
        SELECT UPPER(REPLACE(a.callingstationid,'-',':')) AS mac,
               COUNT(DISTINCT a.username) AS cards,
               COUNT(DISTINCT CONCAT(a.nasipaddress,'|',COALESCE(a.nasportid,''))) AS ports,
               COUNT(*) AS sessions,
               SUM(CASE WHEN a.acctstoptime IS NOT NULL AND COALESCE(a.acctsessiontime,0)<? THEN 1 ELSE 0 END) AS short_sessions,
               SUM(CASE WHEN a.acctstoptime IS NULL THEN 1 ELSE 0 END) AS open_now,
               MAX(a.acctstarttime) AS last_seen
        FROM radacct a
        WHERE a.acctstarttime>=NOW()-INTERVAL ? DAY AND COALESCE(a.callingstationid,'')<>''
        GROUP BY UPPER(REPLACE(a.callingstationid,'-',':'))
        HAVING cards>=? OR ports>=? OR open_now>=2 OR short_sessions>=?
        ORDER BY cards DESC, open_now DESC, short_sessions DESC
        LIMIT ?""", (p['short_seconds'], p['days'], p['min_cards'], p['min_ports'], p['min_short'], p['limit']))
    listed = {row['mac'] for row in list_macs()}
    for row in rows:
        row['listed'] = row['mac'] in listed
        reasons = []
        if int(row['cards'] or 0) >= p['min_cards']:
            reasons.append(f"{row['cards']} كروت")
        if int(row['ports'] or 0) >= p['min_ports']:
            reasons.append(f"{row['ports']} منافذ/VLAN")
        if int(row['open_now'] or 0) >= 2:
            reasons.append(f"{row['open_now']} جلسات مفتوحة معًا")
        if int(row['short_sessions'] or 0) >= p['min_short']:
            reasons.append(f"{row['short_sessions']} جلسة قصيرة")
        row['reasons'] = '، '.join(reasons)
    return rows


# ------------------------------------------------------------ router sync

def profile_words(source, name, fields=COPY_FIELDS):
    """RouterOS API words that add a copy of ``source`` named ``name`` without MAC cookie."""
    words = ['=name=' + name]
    for field in fields:
        if field in source and source[field] not in (None,):
            words.append(f'={field}={source[field]}')
    words.append('=add-mac-cookie=no')
    return words


def _ok(replies):
    kinds = [kind for kind, _ in replies]
    return '!done' in kinds and not any(k in kinds for k in ('!trap', '!fatal'))


def _print(ros, path, query=()):
    replies = ros.talk_raw([path + '/print', *query])
    if not _ok(replies):
        raise RuntimeError(f'{path} unavailable')
    return [row for kind, row in replies if kind == '!re']


def sync_profiles(ros):
    """Ensure every hotspot user profile has its -nocookie copy; returns confirmed copy names."""
    path = '/ip/hotspot/user/profile'
    profiles = _print(ros, path)
    by_name = {row.get('name'): row for row in profiles}
    confirmed, failed = [], []
    for row in profiles:
        name = row.get('name') or ''
        if not name or name.endswith(PROFILE_SUFFIX):
            continue
        target = name + PROFILE_SUFFIX
        existing = by_name.get(target)
        attempts = (COPY_FIELDS, MINIMAL_FIELDS, ())
        done = False
        for fields in attempts:
            words = profile_words(row, target, fields)
            if existing:
                command = [path + '/set', '=.id=' + existing['.id'], *words[1:]]
            else:
                command = [path + '/add', *words]
            if _ok(ros.talk_raw(command)):
                done = True
                break
        (confirmed if done else failed).append(target)
    # Read back: only a copy that exists with the cookie disabled is recorded.
    after = {row.get('name'): row for row in _print(ros, path)}
    verified = [name for name in confirmed if name in after
                and str(after[name].get('add-mac-cookie', '')).lower() in ('false', 'no')]
    return verified, failed + [name for name in confirmed if name not in verified]


def remove_cookies(ros, macs):
    """Delete hotspot MAC cookies of listed MACs (made before they were listed)."""
    if not macs:
        return 0
    wanted, removed = {m.upper() for m in macs}, 0
    for row in _print(ros, '/ip/hotspot/cookie'):
        if str(row.get('mac-address') or '').upper() in wanted and row.get('.id'):
            if _ok(ros.talk_raw(['/ip/hotspot/cookie/remove', '=.id=' + row['.id']])):
                removed += 1
    return removed


def _store_profiles(nas_ip, names):
    from database.db import execute_update, execute_write
    execute_update('DELETE FROM wisp_cloned_mac_profiles WHERE nasipaddress=?', (nas_ip,))
    for name in names:
        execute_write('INSERT INTO wisp_cloned_mac_profiles(nasipaddress,profile,synced_at) VALUES (?,?,NOW())',
                      (nas_ip, name))


def sync_router(device, macs):
    from core.mikrotik_api import RouterOSApiProtocol
    result = dict(nas=device.get('name') or device['ip_address'], ip=device['ip_address'], ok=False,
                  profiles=0, failed=[], cookies=0, error='')
    if not device.get('api_port') or not device.get('api_username'):
        result['error'] = 'لا توجد بيانات API'
        return result
    ros = RouterOSApiProtocol(device['ip_address'], port=int(device['api_port']), timeout=4)
    try:
        ros.connect()
        if not ros.login(device['api_username'], device.get('api_password') or ''):
            result['error'] = 'فشل تسجيل الدخول إلى API'
            return result
        verified, failed = sync_profiles(ros)
        _store_profiles(device['ip_address'], verified)
        result.update(ok=True, profiles=len(verified), failed=failed, cookies=remove_cookies(ros, macs))
    except Exception as exc:
        result['error'] = f'تعذر الاتصال بالراوتر ({type(exc).__name__})'
    finally:
        ros.close()
    return result


def sync_all():
    """Sync every router with API credentials. Unreachable routers keep their last confirmed copies."""
    global _last_sync
    from database.db import query_all
    macs = [row['mac'] for row in list_macs()]
    devices = query_all('SELECT name,ip_address,api_port,api_username,api_password FROM wisp_nas_devices ORDER BY id')
    results = [sync_router(device, macs) for device in devices]
    _last_sync = time.monotonic()
    return results


def maybe_sync(now=None):
    """Periodic sync (every 15 min) while the feature is on and the list is not empty,
    so profiles of packages added later get their copy. Checked at most once a minute."""
    global _last_check
    now = time.monotonic() if now is None else now
    if now - _last_check < CHECK_INTERVAL_SECONDS or (_last_sync and now - _last_sync < SYNC_INTERVAL_SECONDS):
        return None
    _last_check = now
    try:
        if not enabled() or not list_macs():
            return None
        return sync_all()
    except Exception:
        logger.exception('Cloned MAC profile sync failed')
        return None
