"""Cost of consumed data from the configured price of one GB (settings: gb_cost).

Cost = (download + upload bytes) / 1024**3 × gb_cost. A zero or missing price
disables every cost display. The setting is cached briefly per process.
"""
import threading
import time
from decimal import Decimal, InvalidOperation

GB = 1024 ** 3
_cache = {'value': None, 'at': 0.0}
_lock = threading.Lock()


def gb_cost():
    with _lock:
        if _cache['value'] is not None and time.monotonic() - _cache['at'] < 30:
            return _cache['value']
    value = Decimal('0')
    try:
        from database.db import query_one
        row = query_one("SELECT `value` FROM wisp_system_settings WHERE `key` = 'gb_cost'")
        if row and row.get('value') not in (None, ''):
            value = Decimal(str(row['value']))
            if not value.is_finite() or value < 0:
                value = Decimal('0')
    except (InvalidOperation, Exception):
        value = Decimal('0')
    with _lock:
        _cache.update(value=value, at=time.monotonic())
    return value


def clear_cache():
    with _lock:
        _cache.update(value=None, at=0.0)


def cost_enabled():
    return gb_cost() > 0


def cost_for_bytes(total_bytes):
    """Decimal cost of `total_bytes`, or None when cost is disabled or bytes unknown."""
    price = gb_cost()
    if price <= 0 or total_bytes is None:
        return None
    try:
        return (Decimal(int(total_bytes)) / GB * price).quantize(Decimal('0.01'))
    except (TypeError, ValueError, InvalidOperation):
        return None


def format_cost(total_bytes, symbol=''):
    """Display string such as '12.50 ر.ي', or '' when cost display is disabled."""
    amount = cost_for_bytes(total_bytes)
    if amount is None:
        return ''
    text = f'{amount:,.2f}'
    return f'{text} {symbol}'.strip()
