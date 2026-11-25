"""Dashboard router table: live RouterOS counters plus today's traffic and sales per NAS.

Traffic and revenue reuse the network-traffic and sales reports for "today", so
the dashboard never disagrees with the reports. The whole table is cached for a
short time; the dashboard loads it asynchronously and never blocks on routers.
"""
import threading
import time

_CACHE = {'at': 0.0, 'rows': None}
_LOCK = threading.Lock()
TTL_SECONDS = 60


def _today_traffic():
    from services.network_traffic_service import report
    totals = {}
    for point in report({'period': 'today'}).get('points', []):
        address = point.get('nas_address') or ''
        if point.get('total') is not None:
            totals[address] = totals.get(address, 0) + int(point['total'])
    return totals


def _today_revenue():
    from decimal import Decimal
    from services.sales_reporting_service import report
    totals = {}
    for row in report({'period': 'today'}).get('server_breakdown', []) or []:
        address = row.get('nas_address') or ''
        totals[address] = totals.get(address, Decimal('0')) + Decimal(str(row.get('total_gross_revenue') or 0))
    return totals


def router_rows(force=False):
    with _LOCK:
        if not force and _CACHE['rows'] is not None and time.monotonic() - _CACHE['at'] < TTL_SECONDS:
            return _CACHE['rows']
    from core.mikrotik_api import get_all_nas_live_status, uptime_hours
    from core.rate_limit import format_bytes
    from services.data_cost_service import format_cost
    try:
        traffic = _today_traffic()
    except Exception:
        traffic = None
    try:
        revenue = _today_revenue()
    except Exception:
        revenue = None
    rows = []
    for device in get_all_nas_live_status():
        address = device.get('ip_address') or ''
        used = traffic.get(address) if traffic is not None else None
        sold = revenue.get(address) if revenue is not None else None
        online = bool(device.get('is_online'))
        api = bool(device.get('api_connected'))
        rows.append({
            'id': device.get('id'),
            'name': device.get('name') or address,
            'ip_address': address,
            'online': online,
            'api_connected': api,
            'uptime_hours': uptime_hours(device.get('uptime')) if api else None,
            'active': device.get('hotspot_active') if api else None,
            'hosts': device.get('hotspot_hosts') if api else None,
            'neighbors': device.get('neighbors') if api else None,
            'traffic_bytes': used,
            'traffic_str': format_bytes(used) if used is not None else ('0 B' if traffic is not None else 'غير متاح'),
            'traffic_cost': format_cost(used if used is not None else (0 if traffic is not None else None)),
            'revenue': f'{sold:,.2f}' if sold is not None else ('0.00' if revenue is not None else 'غير متاح'),
            'model': device.get('board_name') if api and device.get('board_name') not in (None, '-') else '—',
        })
    with _LOCK:
        _CACHE.update(at=time.monotonic(), rows=rows)
    return rows
