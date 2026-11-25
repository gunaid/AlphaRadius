"""Hotspot domain choices (card@512k/2M|yes): settings, recent choices, router script.

RADIUS does the work (database/realm_policy_schema.py and
docker/freeradius/alpha-realm-policy.conf); this module only serves the page.
"""
import re

from database.realm_policy_schema import DEFAULT_BLOCK_LIST

LIST_NAME = re.compile(r'[A-Za-z0-9_-]{1,32}')

# Update services blocked for addresses in the list. TLS SNI (tls-host) works on
# RouterOS 6.41+ and 7; QUIC (UDP 443) is dropped so apps fall back to TCP.
BLOCKED_TLS_HOSTS = (
    '*.gvt1.com', 'dl.google.com', 'play.googleapis.com', 'play-fe.googleapis.com',
    '*.windowsupdate.com', '*.update.microsoft.com', '*.delivery.mp.microsoft.com',
    'mesu.apple.com', 'updates.cdn-apple.com', 'appldnld.apple.com', 'swcdn.apple.com',
)
BLOCKED_HTTP_CONTENT = ('gvt1.com', 'windowsupdate.com', 'download.windowsupdate.com')


def _setting(key, default):
    from database.db import query_one
    row = query_one('SELECT `value` FROM wisp_system_settings WHERE `key`=?', (key,))
    return str(row['value']) if row and row.get('value') not in (None, '') else default


def _store(key, value, description):
    from database.db import execute_update, execute_write, query_one
    if query_one('SELECT `key` FROM wisp_system_settings WHERE `key`=?', (key,)):
        execute_update('UPDATE wisp_system_settings SET `value`=? WHERE `key`=?', (value, key))
    else:
        execute_write('INSERT INTO wisp_system_settings(`key`,`value`,`description`) VALUES (?,?,?)',
                      (key, value, description))


def settings():
    return dict(enabled=_setting('realm_speed_enabled', '1') != '0',
                block_list=_setting('realm_block_list', DEFAULT_BLOCK_LIST))


def save_settings(form):
    name = str(form.get('block_list') or '').strip() or DEFAULT_BLOCK_LIST
    if not LIST_NAME.fullmatch(name):
        raise ValueError('اسم قائمة الحظر: حروف إنجليزية وأرقام و - و _ فقط، حتى 32 حرفًا.')
    enabled = '1' if form.get('enabled') in ('1', 'on', 'true') else '0'
    _store('realm_speed_enabled', enabled, 'تطبيق السرعة وحظر التحديثات من دومين الهوتسبوت')
    _store('realm_block_list', name, 'قائمة عناوين حظر التحديثات في الراوتر')
    return dict(enabled=enabled == '1', block_list=name)


def recent_choices(limit=200):
    from database.db import query_all
    return query_all('''SELECT username,nasipaddress,callingstationid,realm,rate,block_updates,updated_at
                        FROM wisp_realm_choices ORDER BY updated_at DESC LIMIT ?''', (int(limit),))


def router_script(list_name):
    """Firewall rules for the update-block list (RouterOS 6.41+ and 7)."""
    if not LIST_NAME.fullmatch(list_name or ''):
        list_name = DEFAULT_BLOCK_LIST
    tag = f'comment="ALPHA block updates ({list_name})"'
    lines = ['# ALPHA RADIUS: حظر التحديثات لعناوين القائمة ' + list_name,
             '# الراديوس يضيف IP المستخدم إلى القائمة تلقائيًا عند الدخول بـ yes في الدومين.',
             '/ip firewall filter remove [find where comment~"ALPHA block updates"]',
             f'/ip firewall filter add chain=forward src-address-list={list_name} protocol=udp dst-port=443 '
             f'action=drop {tag} place-before=0']
    for host in BLOCKED_TLS_HOSTS:
        lines.append(f'/ip firewall filter add chain=forward src-address-list={list_name} protocol=tcp '
                     f'dst-port=443 tls-host="{host}" action=reject reject-with=tcp-reset {tag} place-before=0')
    for content in BLOCKED_HTTP_CONTENT:
        lines.append(f'/ip firewall filter add chain=forward src-address-list={list_name} protocol=tcp '
                     f'dst-port=80 content="{content}" action=reject reject-with=tcp-reset {tag} place-before=0')
    return '\n'.join(lines) + '\n'
