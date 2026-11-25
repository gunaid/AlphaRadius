"""Per-manager memory of the last batch-generation form, used as next defaults.

Only presentation defaults are stored; generation still validates every value.
"""
import json

from services.voucher_service import DEFAULT_SALE_POINT, MAX_BATCH_CARDS

FIELDS = ('count', 'format_type', 'char_type', 'same_user_pass', 'code_length',
          'pass_length', 'reseller_id', 'sale_point', 'auto_pdf')
DEFAULTS = {'count': 50, 'format_type': 'pin_only', 'char_type': 'numbers',
            'same_user_pass': False, 'code_length': 8, 'pass_length': 8,
            'reseller_id': '', 'sale_point': DEFAULT_SALE_POINT, 'auto_pdf': False}


def _key(manager_id):
    return f'batch_form_defaults_{int(manager_id or 0)}'


def _int(value, low, high, default):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return number if low <= number <= high else default


def _flag(value):
    # Form posts send '1'/'on'; the stored JSON holds real booleans.
    return value is True or str(value or '').strip().lower() in ('1', 'on', 'true')


def normalize(form):
    values = dict(DEFAULTS)
    values['count'] = _int(form.get('count'), 1, MAX_BATCH_CARDS, DEFAULTS['count'])
    if form.get('format_type') in ('pin_only', 'user_pass'):
        values['format_type'] = form.get('format_type')
    if form.get('char_type') in ('numbers', 'alphanumeric', 'letters'):
        values['char_type'] = form.get('char_type')
    values['same_user_pass'] = _flag(form.get('same_user_pass'))
    values['code_length'] = _int(form.get('code_length'), 4, 32, DEFAULTS['code_length'])
    values['pass_length'] = _int(form.get('pass_length'), 4, 32, DEFAULTS['pass_length'])
    reseller = str(form.get('reseller_id') or '').strip()
    values['reseller_id'] = reseller if reseller.isdigit() else ''
    values['sale_point'] = str(form.get('sale_point') or '').strip()[:100] or DEFAULT_SALE_POINT
    values['auto_pdf'] = _flag(form.get('auto_pdf'))
    return values


def load(manager_id):
    from database.db import query_one
    try:
        row = query_one('SELECT `value` FROM wisp_system_settings WHERE `key` = ?', (_key(manager_id),))
        stored = json.loads(row['value']) if row and row.get('value') else {}
    except Exception:
        stored = {}
    return normalize({**DEFAULTS, **{k: v for k, v in stored.items() if k in FIELDS}}) if stored else dict(DEFAULTS)


def save(manager_id, form):
    """Best effort: a failed save must never fail a committed batch."""
    from database.db import query_one, execute_write
    try:
        value = json.dumps(normalize(form), ensure_ascii=False)
        key = _key(manager_id)
        if query_one('SELECT `key` FROM wisp_system_settings WHERE `key` = ?', (key,)):
            execute_write('UPDATE wisp_system_settings SET `value` = ? WHERE `key` = ?', (value, key))
        else:
            execute_write('INSERT INTO wisp_system_settings (`key`, `value`, `description`) VALUES (?, ?, ?)',
                          (key, value, 'آخر قيم نموذج إنشاء الحزمة'))
    except Exception:
        pass
