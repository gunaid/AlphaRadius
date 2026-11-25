"""Random-MAC roaming: free an idle old seat so the same card can log in again.

A phone that rejoins Wi-Fi with a new random MAC leaves its old hotspot
session behind until the router times it out. While that session holds the
card's only seat, RADIUS rejects the new MAC (fn_reserve_license_slot result
4) and records a request in wisp_roaming_requests.

This worker reads the old session's live idle time from the router itself
(RADIUS interim updates every 180 s are too coarse to tell a gone phone from
an active one):

* idle for at least ``roaming_idle_seconds`` -> disconnect it through the
  normal verified CoA path, so the next attempt of the new MAC passes;
* still passing traffic -> keep it: another device is using the card;
* router unreachable or session unmatched -> change nothing.

Only one seat is freed per request, the most idle one. A disconnect request
is not a Stop: the seat is released when the router's Accounting-Stop
arrives, exactly as for any other disconnect.
"""
import logging
import re
import threading
import time

logger = logging.getLogger(__name__)

POLL_SECONDS = 2
RECHECK_SECONDS = 5          # one router check per account in this window
STALE_CLAIM_SECONDS = 60     # a crashed worker's claim is retried after this
BATCH = 20

ROAMING_IDLE_DEFAULT = 45
ROAMING_IDLE_RANGE = (10, 600)

_last_check = {}
_thread = None
_thread_lock = threading.Lock()


def _mac(value):
    return str(value or '').replace('-', ':').strip().upper()


_UNITS = {'w': 604800, 'd': 86400, 'h': 3600, 'm': 60, 's': 1}


def _idle_seconds(value):
    """RouterOS duration ('1m5s', '00:02:00', '1d02:03:04', '1w2d') to seconds, else None."""
    text = str(value or '').strip().lower()
    if not text:
        return None
    match = re.fullmatch(r'((?:\d+[wd])*)(\d+):(\d{1,2}):(\d{1,2})(?:\.\d+)?', text)
    if match:
        days = sum(int(n) * _UNITS[u] for n, u in re.findall(r'(\d+)([wd])', match[1]))
        return days + int(match[2]) * 3600 + int(match[3]) * 60 + int(match[4])
    if not re.fullmatch(r'(?:\d+(?:ms|[wdhms]))+', text):
        return None
    return sum(int(n) * _UNITS[u] for n, u in re.findall(r'(\d+)(ms|[wdhms])', text) if u != 'ms')


def choose_idle_session(sessions, router_rows, idle_threshold, new_mac=''):
    """Pick the open session to replace, or explain why none is replaced.

    sessions:    open radacct rows of the account.
    router_rows: {nas_ip: [hotspot active rows for the account]} or
                 {nas_ip: None} when that router could not be read.
    Returns (session, idle_seconds, outcome); session is None unless the
    outcome is 'kicked'. Outcomes: kicked, live, unverified, absent, no_session.
    """
    if not sessions:
        return None, None, 'no_session'
    candidates, live, unverified, absent = [], 0, 0, 0
    for row in sessions:
        if str(row.get('framedprotocol') or '').upper() == 'PPP':
            live += 1          # PPPoE has no hotspot idle time; never replaced here
            continue
        hosts = router_rows.get(row.get('nasipaddress'))
        if hosts is None:
            unverified += 1
            continue
        mac, address = _mac(row.get('callingstationid')), str(row.get('framedipaddress') or '')
        match = [h for h in hosts if _mac(h.get('mac-address')) == mac
                 and (not address or str(h.get('address') or '') == address)]
        if len(match) != 1:
            absent += 1        # ghost or ambiguous: no live proof either way
            continue
        idle = _idle_seconds(match[0].get('idle-time'))
        if idle is None:
            unverified += 1
        elif idle >= idle_threshold:
            candidates.append((idle, row))
        else:
            live += 1
    if candidates:
        idle, row = max(candidates, key=lambda item: item[0])
        return row, idle, 'kicked'
    if unverified:
        return None, None, 'unverified'
    if live:
        return None, None, 'live'
    return None, None, 'absent'


def parse_roaming_idle(raw):
    """Seconds without traffic before an old session may be replaced (10–600)."""
    text = str(raw or '').strip()
    if not text:
        return ROAMING_IDLE_DEFAULT
    if not text.isdigit() or not ROAMING_IDLE_RANGE[0] <= int(text) <= ROAMING_IDLE_RANGE[1]:
        raise ValueError('مدة الخمول للانتقال يجب أن تكون بين 10 و600 ثانية.')
    return int(text)


def settings():
    from database.db import query_all
    values = {r['key']: r['value'] for r in query_all(
        "SELECT `key`,`value` FROM wisp_system_settings WHERE `key` IN ('roaming_enabled','roaming_idle_seconds')")}
    try:
        idle = parse_roaming_idle(values.get('roaming_idle_seconds'))
    except ValueError:
        idle = ROAMING_IDLE_DEFAULT
    return str(values.get('roaming_enabled', '1')) != '0', idle


def _router_hosts(nas_ip, username):
    """Hotspot active rows of this account on one router, or None if unreadable."""
    from services.coa_queue_service import _resolve_nas_credentials
    from core.mikrotik_api import RouterOSApiProtocol
    resolved, _secret, _coa, api_port, api_user, api_pass = _resolve_nas_credentials(nas_ip)
    if not api_port or not api_user:
        return None
    ros = RouterOSApiProtocol(resolved or nas_ip, port=int(api_port), timeout=2.5)
    try:
        ros.connect()
        if not ros.login(api_user, api_pass):
            return None
        replies = ros.talk_raw(['/ip/hotspot/active/print', '?user=' + username])
        kinds = [kind for kind, _ in replies]
        if '!done' not in kinds or any(k in kinds for k in ('!trap', '!fatal')):
            return None
        return [row for kind, row in replies
                if kind == '!re' and str(row.get('user', '')).casefold() == username.casefold()]
    except Exception as exc:
        logger.info('Roaming check could not read router %s: %s', nas_ip, type(exc).__name__)
        return None
    finally:
        ros.close()


def _claim(username, requested_at):
    from database.db import execute_update
    return execute_update(
        """UPDATE wisp_roaming_requests SET status='checking',processed_at=NOW(),attempts=attempts+1
           WHERE username=? AND requested_at=? AND (status='pending'
             OR (status='checking' AND processed_at<NOW()-INTERVAL ? SECOND))""",
        (username, requested_at, STALE_CLAIM_SECONDS)) == 1


def _finish(request, outcome, detail, old_mac='', idle=None):
    from database.db import execute_update, execute_write
    # A newer rejected attempt resets the row to pending; leave that one queued.
    execute_update("""UPDATE wisp_roaming_requests SET status=?,processed_at=NOW(),detail=?
                      WHERE username=? AND requested_at=? AND status='checking'""",
                   (outcome, detail[:191], request['username'], request['requested_at']))
    execute_write("""INSERT INTO wisp_roaming_events
                     (username,nasipaddress,new_mac,old_mac,idle_seconds,outcome,created_at)
                     VALUES (?,?,?,?,?,?,NOW())""",
                  (request['username'], request.get('nasipaddress') or '', request.get('callingstationid') or '',
                   old_mac or '', idle, outcome))


def process_request(request, idle_threshold):
    from database.db import query_all
    username = request['username']
    sessions = query_all("""SELECT radacctid,nasipaddress,callingstationid,framedipaddress,acctsessionid,framedprotocol
                            FROM radacct WHERE username=? AND acctstoptime IS NULL""", (username,))
    routers = {nas: _router_hosts(nas, username) for nas in {s['nasipaddress'] for s in sessions}}
    session, idle, outcome = choose_idle_session(sessions, routers, idle_threshold, request.get('callingstationid'))
    if session is None:
        _finish(request, outcome, {'live': 'الجلسة السابقة نشطة', 'unverified': 'تعذر قراءة الراوتر',
                                   'absent': 'الجلسة غير موجودة على الراوتر', 'no_session': 'لا جلسة مفتوحة'}[outcome])
        return outcome
    from services.coa_queue_service import enqueue_disconnect
    accepted, message = enqueue_disconnect(
        username, nas_ip=session['nasipaddress'], framed_ip=session.get('framedipaddress'),
        session_id=session.get('acctsessionid'), mac_address=session.get('callingstationid'),
        radacctid=session['radacctid'], reason='Roaming: idle session replaced', admin_username='system')
    outcome = 'kicked' if accepted else 'queue_failed'
    _finish(request, outcome, f'خمول {idle} ثانية' if accepted else message,
            old_mac=session.get('callingstationid'), idle=idle)
    return outcome


def process_pending():
    from database.db import query_all
    enabled, idle_threshold = settings()
    if not enabled:
        return 0
    rows = query_all("""SELECT * FROM wisp_roaming_requests WHERE status='pending'
                          OR (status='checking' AND processed_at<NOW()-INTERVAL ? SECOND)
                        ORDER BY requested_at LIMIT ?""", (STALE_CLAIM_SECONDS, BATCH))
    done = 0
    now = time.monotonic()
    for request in rows:
        if now - _last_check.get(request['username'], -RECHECK_SECONDS) < RECHECK_SECONDS:
            continue
        if not _claim(request['username'], request['requested_at']):
            continue
        _last_check[request['username']] = now
        try:
            process_request(request, idle_threshold)
            done += 1
        except Exception:
            logger.exception('Roaming request failed')
            try:
                _finish(request, 'error', 'خطأ داخلي')
            except Exception:
                pass
    if len(_last_check) > 5000:
        for name, at in list(_last_check.items()):
            if now - at > RECHECK_SECONDS:
                _last_check.pop(name, None)
    return done


def _loop():
    while True:
        try:
            process_pending()
        except Exception:
            logger.exception('Roaming worker cycle failed')
        time.sleep(POLL_SECONDS)


def start_worker():
    global _thread
    with _thread_lock:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_loop, name='RoamingWorker', daemon=True)
            _thread.start()
