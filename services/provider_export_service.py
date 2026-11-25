"""Batch export for card providers (e.g. https://kurootalshabakah.tabweeb.com.ye/).

The provider accepts only the cards themselves:
* PDF: a grid of boxes, each holding the card code and nothing else;
* Excel: one card per row, no header or other columns.

Only cards still unused are exported, so a card that was already activated is
never handed to a provider. The card code is the username (PIN cards and
"password = username" cards); when the password differs, the password follows
it (second line in the PDF box, second column in Excel).
"""
import html
import io

COLUMNS, ROWS = 4, 12              # 48 boxes per A4 page
PAGE_BOXES = COLUMNS * ROWS
_UNSAFE = ('\r', '\n', '\x00', '\x85', ' ', ' ')


def card_values(card):
    username, password = card.get('username'), card.get('password')
    for value in (username, password):
        if value is not None and (not isinstance(value, str) or any(c in value for c in _UNSAFE)):
            raise ValueError('يوجد كرت بقيمة غير صالحة للتصدير.')
    if not username:
        raise ValueError('يوجد كرت بلا اسم مستخدم.')
    return [username] if not password or password == username else [username, password]


def provider_cards(batch_id, owner=None):
    """(batch, rows, skipped): unused cards in serial order, from one read snapshot."""
    from database.db import adapt_query, get_connection, is_mysql_conn
    conn = get_connection()
    try:
        cur = conn.cursor()
        if is_mysql_conn(conn):
            cur.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            cur.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')

        def rows(sql, args):
            cur.execute(adapt_query(sql, conn), args)
            names = [c[0] for c in cur.description]
            return [dict(r) if hasattr(r, 'keys') else dict(zip(names, r)) for r in cur.fetchall()]
        batches = rows('SELECT id, name, reseller_id, sale_point FROM wisp_voucher_batches WHERE id = ?', (batch_id,))
        if not batches or (owner is not None and batches[0]['reseller_id'] != owner):
            raise LookupError('الحزمة غير موجودة.')
        cards = rows('''SELECT id, username, password, status, reseller_id FROM wisp_vouchers
                        WHERE batch_id = ? ORDER BY serial_number, id''', (batch_id,))
        conn.rollback()
    finally:
        conn.close()
    if owner is not None and any(card['reseller_id'] != owner for card in cards):
        raise LookupError('الحزمة غير موجودة.')
    unused = [card_values(c) for c in cards if c.get('status') == 'unused']
    return batches[0], unused, len(cards) - len(unused)


def workbook(values):
    """One card per row, codes stored as text (leading zeros kept), no header."""
    from openpyxl import Workbook
    book = Workbook()
    sheet = book.active
    sheet.title = 'cards'
    for row in values:
        sheet.append(row)
    for column in sheet.iter_cols():
        for cell in column:
            cell.number_format = '@'
            cell.data_type = 's'
    sheet.column_dimensions['A'].width = 22
    sheet.column_dimensions['B'].width = 22
    buffer = io.BytesIO()
    book.save(buffer)
    buffer.seek(0)
    return buffer


def pdf_pages(values, per_part=PAGE_BOXES * 20):
    """HTML parts (20 pages each) of plain boxes with the card code only."""
    style = '''<style>
@page { size: A4 portrait; margin: 10mm; }
html, body { margin: 0; padding: 0; background: #fff; }
.page { display: grid; grid-template-columns: repeat(%d, 1fr); grid-auto-rows: 22mm; gap: 0;
        break-after: page; page-break-after: always; }
.page:last-child { break-after: auto; page-break-after: auto; }
.box { border: 0.4mm solid #000; display: flex; flex-direction: column; align-items: center; justify-content: center;
       font-family: "DejaVu Sans Mono", "Liberation Mono", monospace; font-weight: 700; color: #000;
       font-size: 15pt; overflow: hidden; box-sizing: border-box; margin: -0.2mm 0 0 -0.2mm; }
.box.two { font-size: 12pt; line-height: 1.35; }
</style>''' % COLUMNS
    for start in range(0, max(len(values), 1), per_part):
        chunk = values[start:start + per_part]
        pages = []
        for offset in range(0, len(chunk), PAGE_BOXES):
            boxes = ''.join('<div class="box%s">%s</div>' % (' two' if len(v) > 1 else '',
                                                              '<br>'.join(html.escape(x) for x in v))
                            for v in chunk[offset:offset + PAGE_BOXES])
            pages.append('<div class="page">' + boxes + '</div>')
        yield '<!DOCTYPE html><html><head><meta charset="utf-8">' + style + '</head><body>' + ''.join(pages) + '</body></html>'


def download_name(batch_id, extension, fallback):
    from services.batch_export_service import batch_export_name
    name = batch_export_name(batch_id, extension, fallback)
    base, dot, ext = name.rpartition('.')
    return f'{base}-مزود.{ext}' if dot else name
