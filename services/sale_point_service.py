"""Sale points: shops, e-wallets and card providers that sell batches.

A batch keeps its sale point as a name (wisp_voucher_batches.sale_point), so
existing batches and reports need no migration. This list only names the
choices offered when creating or editing a batch, and marks which ones are
card providers (their batches are exported in the provider format).
"""
KINDS = (('shop', 'نقطة بيع / كشك'), ('wallet', 'محفظة إلكترونية'), ('provider', 'مزود كروت'), ('other', 'أخرى'))
KIND_NAMES = dict(KINDS)
SEED_FLAG = 'sale_points_seed_20261125'
SEED = (('توزيع عام', 'shop', ''),
        ('كروت الشبكة (tabweeb)', 'provider', 'https://kurootalshabakah.tabweeb.com.ye/ — PDF مربعات أو Excel صفوف'))

TABLE_SQL = """CREATE TABLE IF NOT EXISTS wisp_sale_points (
 id INT AUTO_INCREMENT PRIMARY KEY,
 name VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 kind VARCHAR(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'shop',
 note VARCHAR(250) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
 is_active TINYINT NOT NULL DEFAULT 1,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE KEY uq_sale_point_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""
SQLITE_SQL = """CREATE TABLE IF NOT EXISTS wisp_sale_points (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL DEFAULT 'shop',
 note TEXT NOT NULL DEFAULT '', is_active INTEGER NOT NULL DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"""


def ensure_table():
    from database.db import execute_write, get_connection, is_mysql_conn, query_one
    conn = get_connection()
    try:
        mysql = is_mysql_conn(conn)
    finally:
        conn.close()
    execute_write(TABLE_SQL if mysql else SQLITE_SQL)
    if not query_one('SELECT `key` FROM wisp_system_settings WHERE `key` = ?', (SEED_FLAG,)):
        for name, kind, note in SEED:
            if not query_one('SELECT id FROM wisp_sale_points WHERE name = ?', (name,)):
                execute_write('INSERT INTO wisp_sale_points (name, kind, note) VALUES (?, ?, ?)', (name, kind, note))
        execute_write('INSERT INTO wisp_system_settings (`key`, `value`, `description`) VALUES (?, ?, ?)',
                      (SEED_FLAG, '1', 'نقاط البيع المبدئية'))


def clean(form):
    name = ' '.join(str(form.get('name') or '').split())[:100]
    if not name:
        raise ValueError('اسم نقطة البيع مطلوب.')
    kind = form.get('kind') if form.get('kind') in KIND_NAMES else 'shop'
    note = ' '.join(str(form.get('note') or '').split())[:250]
    return name, kind, note


def list_points(active_only=False):
    from database.db import query_all
    try:
        rows = query_all('SELECT * FROM wisp_sale_points' + (' WHERE is_active = 1' if active_only else '')
                         + ' ORDER BY is_active DESC, name')
    except Exception:
        return []
    for row in rows:
        row['kind_name'] = KIND_NAMES.get(row.get('kind'), row.get('kind'))
    return rows


def save_point(form, point_id=None):
    """Add, or rename/edit; a rename also renames the batches that carried the old name."""
    from database.db import execute_update, execute_write, query_one
    name, kind, note = clean(form)
    clash = query_one('SELECT id FROM wisp_sale_points WHERE name = ?', (name,))
    if clash and (point_id is None or int(clash['id']) != int(point_id)):
        raise ValueError('يوجد نقطة بيع بهذا الاسم.')
    if point_id is None:
        execute_write('INSERT INTO wisp_sale_points (name, kind, note) VALUES (?, ?, ?)', (name, kind, note))
        return name
    old = query_one('SELECT name FROM wisp_sale_points WHERE id = ?', (int(point_id),))
    if not old:
        raise ValueError('نقطة البيع غير موجودة.')
    execute_update('UPDATE wisp_sale_points SET name = ?, kind = ?, note = ? WHERE id = ?', (name, kind, note, int(point_id)))
    if old['name'] != name:
        execute_update('UPDATE wisp_voucher_batches SET sale_point = ? WHERE sale_point = ?', (name, old['name']))
    return name


def toggle_point(point_id):
    from database.db import execute_update
    return execute_update('UPDATE wisp_sale_points SET is_active = 1 - is_active WHERE id = ?', (int(point_id),)) > 0


def batch_counts():
    """Batches and cards per sale point name (all time)."""
    from database.db import query_all
    try:
        rows = query_all('''SELECT COALESCE(NULLIF(b.sale_point,''),'توزيع عام') AS name, COUNT(DISTINCT b.id) AS batches,
                            COUNT(v.id) AS cards, SUM(CASE WHEN v.status = 'unused' THEN 1 ELSE 0 END) AS unused
                            FROM wisp_voucher_batches b LEFT JOIN wisp_vouchers v ON v.batch_id = b.id
                            GROUP BY COALESCE(NULLIF(b.sale_point,''),'توزيع عام')''')
    except Exception:
        return {}
    return {r['name']: r for r in rows}
