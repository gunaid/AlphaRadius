"""Comprehensive report: sales, consumption and their best performers in one period.

Read-only, one consistent snapshot. Sources and rules:

* Cards sold = first activations (wisp_voucher_sales.first_activation_voucher_id),
  i.e. counted at first login; renewals are the other voucher sales rows.
* Sale point = the batch's sale_point; reseller = the sale's reseller_id.
* Sales per router/hotspot server (VLAN, port) come from wisp_sale_sources.
* Consumption (bytes, hours, users, sessions) comes from
  network_traffic_service.sessions_sql: live, archived, imported and settled
  history deduplicated by session identity, sessions started in the period.
  The dashboard's measured total for the period is shown beside it when the
  measurement history is available.
* A reseller (owner) sees only their own sales and sessions; reseller ranking,
  subscriber invoices and system-wide counters are admin-only.
"""
import datetime as dt
from decimal import Decimal
from zoneinfo import ZoneInfo

from services.sales_reporting_service import date_bounds

PERIODS = [('today', 'اليوم'), ('yesterday', 'الأمس'), ('this_week', 'آخر 7 أيام'),
           ('this_month', 'هذا الشهر'), ('last_month', 'الشهر السابق'), ('this_year', 'هذا العام'),
           ('all', 'كامل المدة'), ('custom', 'نطاق مخصص')]
STORAGE = dt.timezone(dt.timedelta(hours=3))
GB = 1024 ** 3
DEFAULT_SALE_POINT = 'توزيع عام'
TOP = 15


def selected_filters(args, now=None, timezone='Asia/Aden'):
    selected = {key: str(args.get(key, default) or default).strip()
                for key, default in (('period', 'this_month'), ('date_from', ''), ('date_to', ''))}
    start, end = date_bounds(selected['period'], selected['date_from'], selected['date_to'], now, timezone)
    return selected, start, end


def _int(value):
    return int(value or 0)


def _money(value):
    return Decimal(str(value or 0)).quantize(Decimal('0.01'))


def _range(column, start, end, values):
    clauses = []
    if start:
        clauses.append(column + '>=%s'); values.append(start)
    if end:
        clauses.append(column + '<%s'); values.append(end)
    return clauses


# ------------------------------------------------------------------- sales

def sales_sections(query, owner, start, end, timezone):
    values = []
    clauses = _range('s.activated_at', start, end, values)
    if owner is not None:
        clauses.append('s.reseller_id=%s'); values.append(int(owner))
    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    params = tuple(values)
    measures = '''SUM(s.first_activation_voucher_id IS NOT NULL) AS sold,
        SUM(s.first_activation_voucher_id IS NULL) AS renewals,
        COALESCE(SUM(s.price),0) AS revenue, COALESCE(SUM(s.cost),0) AS cost'''
    summary = query(f'SELECT {measures}, COUNT(DISTINCT s.voucher_id) AS cards FROM wisp_voucher_sales s{where}', params)[0]
    packages = query(f'''SELECT s.package_name AS name,{measures} FROM wisp_voucher_sales s{where}
        GROUP BY s.package_name ORDER BY revenue DESC, sold DESC LIMIT {TOP * 2}''', params)
    sale_points = query(f'''SELECT COALESCE(NULLIF(TRIM(b.sale_point),''),%s) AS name,{measures}
        FROM wisp_voucher_sales s LEFT JOIN wisp_voucher_batches b ON b.id=s.batch_id{where}
        GROUP BY COALESCE(NULLIF(TRIM(b.sale_point),''),%s) ORDER BY revenue DESC LIMIT {TOP * 2}''',
                        (DEFAULT_SALE_POINT,) + params + (DEFAULT_SALE_POINT,))
    resellers = []
    if owner is None:
        resellers = query(f'''SELECT s.reseller_id AS id,
            COALESCE(NULLIF(m.full_name,''),m.username,r.name) AS name,{measures}
            FROM wisp_voucher_sales s
            LEFT JOIN wisp_managers m ON m.id=s.reseller_id
            LEFT JOIN wisp_resellers r ON r.id=s.reseller_id AND m.id IS NULL{where}
            GROUP BY s.reseller_id, COALESCE(NULLIF(m.full_name,''),m.username,r.name)
            ORDER BY revenue DESC LIMIT {TOP * 2}''', params)
        for row in resellers:
            row['name'] = row['name'] or ('بيع مباشر' if row['id'] is None else f"موزع #{row['id']}")
    points = query(f'''SELECT x.server_key, x.nas_address, x.nas_label, x.service_type, x.server_name,
        x.server_interface,{measures}
        FROM wisp_voucher_sales s JOIN wisp_sale_sources x ON x.event_kind='voucher' AND x.event_id=s.id{where}
        GROUP BY x.server_key, x.nas_address, x.nas_label, x.service_type, x.server_name, x.server_interface''', params)
    buckets = query(f'''SELECT DATE_FORMAT(s.activated_at,'%%Y-%%m-%%d %%H:00:00') AS bucket,{measures}
        FROM wisp_voucher_sales s{where} GROUP BY DATE_FORMAT(s.activated_at,'%%Y-%%m-%%d %%H:00:00')''', params)
    for rows in (packages, sale_points, resellers, points, buckets):
        for row in rows:
            _sales_numbers(row)
    _sales_numbers(summary)
    days, hours = time_series(buckets, timezone)
    return dict(summary=summary, packages=packages, sale_points=sale_points, resellers=resellers,
                sale_points_by_server=points, days=days, hours=hours)


def _sales_numbers(row):
    for key in ('sold', 'renewals', 'cards'):
        if key in row:
            row[key] = _int(row[key])
    row['revenue'], row['cost'] = _money(row.get('revenue')), _money(row.get('cost'))
    row['profit'] = row['revenue'] - row['cost']
    return row


def time_series(buckets, timezone):
    """Hourly storage-time buckets -> per local day and per local hour of day."""
    zone = ZoneInfo(timezone)
    days, hours = {}, {h: dict(hour=h, sold=0, renewals=0, revenue=Decimal('0.00')) for h in range(24)}
    for row in buckets:
        at = row['bucket']
        if isinstance(at, str):
            at = dt.datetime.strptime(at, '%Y-%m-%d %H:%M:%S')
        local = at.replace(tzinfo=STORAGE).astimezone(zone)
        day = days.setdefault(local.date().isoformat(), dict(day=local.date().isoformat(), sold=0, renewals=0,
                                                              revenue=Decimal('0.00'), cost=Decimal('0.00')))
        for target in (day, hours[local.hour]):
            target['sold'] += row['sold']
            target['renewals'] += row['renewals']
            target['revenue'] += row['revenue']
        day['cost'] += row['cost']
    return [days[k] for k in sorted(days)], [hours[h] for h in range(24)]


# ------------------------------------------------------------- consumption

def consumption_sections(query, owner, start, end, catalog):
    from services.network_traffic_service import sessions_sql, point_info
    source, params = sessions_sql(owner, start, end, with_seconds=True)
    totals = query(f'''SELECT COALESCE(SUM(session_weight),0) AS sessions, COUNT(DISTINCT username) AS users,
        SUM(download) AS download, SUM(upload) AS upload, SUM(seconds) AS seconds,
        SUM(stopped_at IS NULL) AS open_sessions FROM {source}''', params)[0]
    raw_points = query(f'''SELECT nasipaddress AS nas_address, service_type, server_name,
        CASE WHEN service_type='pppoe' THEN server_interface ELSE '' END AS server_interface,
        SUM(session_weight) AS sessions, COUNT(DISTINCT username) AS users,
        SUM(download) AS download, SUM(upload) AS upload, SUM(seconds) AS seconds
        FROM {source} GROUP BY nasipaddress, service_type, server_name,
        CASE WHEN service_type='pppoe' THEN server_interface ELSE '' END''', params)
    per_user = f'''SELECT username, SUM(session_weight) AS sessions, SUM(download) AS download,
        SUM(upload) AS upload, SUM(seconds) AS seconds FROM {source} GROUP BY username'''
    account = '''LEFT JOIN wisp_vouchers v ON v.username=CONVERT(u.username USING utf8mb4) COLLATE utf8mb4_unicode_ci
        LEFT JOIN wisp_subscribers sb ON v.id IS NULL AND sb.username=CONVERT(u.username USING utf8mb4) COLLATE utf8mb4_unicode_ci
        LEFT JOIN wisp_packages p ON p.id=COALESCE(v.package_id, sb.package_id)'''
    packages = query(f'''SELECT COALESCE(p.name,'غير معروف') AS name, COUNT(*) AS users,
        SUM(u.sessions) AS sessions, SUM(u.download) AS download, SUM(u.upload) AS upload, SUM(u.seconds) AS seconds
        FROM ({per_user}) u {account} GROUP BY COALESCE(p.name,'غير معروف')''', params)
    top_users = query(f'''SELECT u.username, COALESCE(p.name,'') AS package, u.sessions, u.download, u.upload, u.seconds
        FROM ({per_user}) u {account}
        ORDER BY COALESCE(u.download,0)+COALESCE(u.upload,0) DESC LIMIT {TOP}''', params)
    _usage_numbers(totals)
    points = {}
    for row in raw_points:
        info = point_info(row, catalog)
        point = points.setdefault(info['server_key'], dict(info, sessions=0, users=0, download=0, upload=0, seconds=0))
        for key in ('sessions', 'users', 'download', 'upload', 'seconds'):
            point[key] += _int(row.get(key))
    for rows in (list(points.values()), packages, top_users):
        for row in rows:
            _usage_numbers(row)
    rank = lambda rows: sorted(rows, key=lambda r: (r['total'], r['seconds']), reverse=True)
    return dict(totals=totals, points=rank(points.values()), packages=rank(packages), top_users=top_users)


def _usage_numbers(row):
    for key in ('sessions', 'users', 'download', 'upload', 'seconds', 'open_sessions'):
        if key in row:
            row[key] = _int(row[key])
    row['total'] = row.get('download', 0) + row.get('upload', 0)
    row['hours'] = round(row.get('seconds', 0) / 3600, 1)
    return row


# --------------------------------------------------------------- combining

def merge_points(usage_points, sale_points):
    """One row per router/hotspot server with consumption and sales together."""
    merged = {p['server_key']: dict(p, sold=0, renewals=0, revenue=Decimal('0.00')) for p in usage_points}
    for row in sale_points:
        key = row.get('server_key') or 'unknown'
        point = merged.get(key)
        if point is None:
            point = merged[key] = dict(server_key=key, nas_address=row.get('nas_address') or '',
                                       nas_label=row.get('nas_label') or row.get('nas_address') or 'غير محدد',
                                       server_label=row.get('server_name') or 'غير محدد',
                                       service_type=row.get('service_type') or '',
                                       sessions=0, users=0, download=0, upload=0, seconds=0, total=0, hours=0.0,
                                       sold=0, renewals=0, revenue=Decimal('0.00'))
        point['sold'] += row['sold']
        point['renewals'] += row['renewals']
        point['revenue'] += row['revenue']
    return sorted(merged.values(), key=lambda p: (p['total'], p['revenue']), reverse=True)


def kpis(sales, usage, gb_price, extra):
    s, u = sales['summary'], usage['totals']
    data_cost = (Decimal(u['total']) / GB * gb_price).quantize(Decimal('0.01')) if gb_price else None
    best = lambda rows, key: max(rows, key=lambda r: r[key]) if rows and max(r[key] for r in rows) else None
    peak = best(sales['hours'], 'sold')
    return dict(
        sold=s['sold'], renewals=s['renewals'], revenue=s['revenue'], cost=s['cost'], profit=s['profit'],
        data_cost=data_cost, net=(s['profit'] - data_cost) if data_cost is not None else None,
        avg_price=(s['revenue'] / (s['sold'] + s['renewals'])).quantize(Decimal('0.01')) if s['sold'] + s['renewals'] else None,
        bytes=u['total'], hours=u['hours'], users=u['users'], sessions=u['sessions'],
        bytes_per_user=(u['total'] // u['users']) if u['users'] else None,
        hours_per_user=round(u['hours'] / u['users'], 1) if u['users'] else None,
        peak_hour=peak['hour'] if peak else None,
        best_package=best(sales['packages'], 'revenue'), best_sale_point=best(sales['sale_points'], 'revenue'),
        best_reseller=best(sales['resellers'], 'revenue'),
        best_point=best(usage['points'], 'total'), best_day=best(sales['days'], 'revenue'),
        most_used_package=best(usage['packages'], 'total'),
        **extra)


def admin_extras(query, start, end):
    """Counters that only make sense system-wide; missing tables read as none."""
    out = dict(invoices=None, active_now=None, roaming={})
    values = []
    clauses = _range('i.paid_at', start, end, values)
    clauses.append("i.status='paid'")
    clauses.append("COALESCE(i.package_name,'') NOT IN ('إيداع رصيد محفظة','سحب/تصحيح رصيد محفظة')")
    row = query('SELECT COUNT(*) AS count, COALESCE(SUM(i.amount),0) AS amount FROM wisp_invoices i WHERE '
                + ' AND '.join(clauses), tuple(values))[0]
    out['invoices'] = dict(count=_int(row['count']), amount=_money(row['amount']))
    out['active_now'] = _int(query('''SELECT COUNT(*) AS n FROM radacct WHERE acctstoptime IS NULL
        AND COALESCE(acctupdatetime,acctstarttime)>=NOW()-INTERVAL 5 MINUTE''')[0]['n'])
    try:
        values = []
        clauses = _range('created_at', start, end, values)
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        out['roaming'] = {r['outcome']: _int(r['n']) for r in query(
            f'SELECT outcome, COUNT(*) AS n FROM wisp_roaming_events{where} GROUP BY outcome', tuple(values))}
    except Exception:
        out['roaming'] = {}
    return out


def measured_total(selected, now, timezone):
    """The dashboard's measured bytes for the same period, or None if unavailable."""
    try:
        from services.network_traffic_service import report as traffic_report
        data = traffic_report(dict(selected, basis='measured', traffic_sort='total', traffic_dir='desc'), now, timezone)
        return data['totals'].get('total')
    except Exception:
        return None


def report(args, now=None, timezone=None):
    from core.ownership import owner_id
    from core.time_service import get_configured_timezone_name
    from database.db import get_connection
    from services.data_cost_service import gb_cost
    timezone = timezone or get_configured_timezone_name()
    selected, start, end = selected_filters(args, now, timezone)
    owner = owner_id()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')

            def query(sql, params=()):
                cur.execute(sql, params)
                return list(cur.fetchall())
            catalog = {}
            for item in query('''SELECT ip_address AS address, name AS label FROM wisp_nas_devices
                                 UNION ALL SELECT nasname, shortname FROM nas'''):
                if item['address'] and str(item['label'] or '').strip():
                    catalog.setdefault(item['address'], item['label'].strip())
            sales = sales_sections(query, owner, start, end, timezone)
            usage = consumption_sections(query, owner, start, end, catalog)
            extra = admin_extras(query, start, end) if owner is None else dict(invoices=None, active_now=None, roaming={})
        conn.rollback()
    finally:
        conn.close()
    gb_price = gb_cost()
    points = merge_points(usage['points'], sales['sale_points_by_server'])
    return dict(selected=selected, periods=PERIODS, owner_view=owner is not None, timezone=timezone,
                generated_at=(now or dt.datetime.now(dt.timezone.utc)).astimezone(ZoneInfo(timezone)),
                kpi=kpis(sales, usage, gb_price, dict(extra, measured_bytes=measured_total(selected, now, timezone))),
                sales=sales, usage=usage, points=points, gb_price=gb_price)


# ------------------------------------------------------------------ export

def workbook(data):
    """All sections as one .xlsx (one sheet per table)."""
    from openpyxl import Workbook
    from services.network_traffic_service import format_bytes
    book = Workbook()
    sheet = book.active
    sheet.title = 'الملخص'
    sheet.sheet_view.rightToLeft = True
    k = data['kpi']
    for label, value in (('الفترة', data['selected']['period']), ('كروت مباعة (أول دخول)', k['sold']),
                         ('تجديدات', k['renewals']), ('الإيراد', k['revenue']), ('التكلفة', k['cost']),
                         ('الربح', k['profit']), ('تكلفة البيانات', k['data_cost']), ('الصافي', k['net']),
                         ('الاستهلاك', format_bytes(k['bytes'])), ('الساعات', k['hours']),
                         ('المستخدمون', k['users']), ('الجلسات', k['sessions'])):
        sheet.append([label, '' if value is None else (float(value) if isinstance(value, Decimal) else value)])

    def table(title, headers, rows):
        ws = book.create_sheet(title[:31])
        ws.sheet_view.rightToLeft = True
        ws.append(headers)
        for row in rows:
            ws.append([float(v) if isinstance(v, Decimal) else v for v in row])
    s, u = data['sales'], data['usage']
    sales_head = ['الاسم', 'كروت مباعة', 'تجديدات', 'الإيراد', 'التكلفة', 'الربح']
    sales_row = lambda r: [r['name'], r['sold'], r['renewals'], r['revenue'], r['cost'], r['profit']]
    table('الباقات - المبيعات', sales_head, map(sales_row, s['packages']))
    table('نقاط البيع', sales_head, map(sales_row, s['sale_points']))
    if s['resellers']:
        table('الموزعون', sales_head, map(sales_row, s['resellers']))
    table('السيرفرات والمنافذ', ['الراوتر', 'السيرفر/المنفذ', 'النوع', 'كروت مباعة', 'الإيراد', 'المستخدمون',
                                  'الجلسات', 'الاستهلاك بايت', 'الساعات'],
          ([p['nas_label'], p['server_label'], p['service_type'], p['sold'], p['revenue'], p['users'],
            p['sessions'], p['total'], p['hours']] for p in data['points']))
    table('الباقات - الاستهلاك', ['الباقة', 'المستخدمون', 'الجلسات', 'الاستهلاك بايت', 'الساعات'],
          ([r['name'], r['users'], r['sessions'], r['total'], r['hours']] for r in u['packages']))
    table('الأيام', ['اليوم', 'كروت مباعة', 'تجديدات', 'الإيراد', 'التكلفة'],
          ([d['day'], d['sold'], d['renewals'], d['revenue'], d['cost']] for d in s['days']))
    table('ساعات اليوم', ['الساعة', 'كروت مباعة', 'تجديدات', 'الإيراد'],
          ([h['hour'], h['sold'], h['renewals'], h['revenue']] for h in s['hours']))
    table('أعلى المستخدمين', ['المستخدم', 'الباقة', 'الجلسات', 'الاستهلاك بايت', 'الساعات'],
          ([r['username'], r['package'], r['sessions'], r['total'], r['hours']] for r in u['top_users']))
    import io
    buffer = io.BytesIO()
    book.save(buffer)
    buffer.seek(0)
    return buffer
