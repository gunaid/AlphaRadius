"""SQLite stand-in for database.db.db_session in isolated contract fixtures.

transaction(db) yields a connection with the shape production code expects from
a PyMySQL DictCursor connection, backed by the fixture's in-memory SQLite DB:

* cursor() objects work as context managers (``with conn.cursor() as cur``);
* rows are dicts that also accept integer indexes, so ``row['x']``,
  ``row.get('x')``, ``dict(row)`` and ``row[0]`` all work;
* MySQL-only lock clauses (FOR UPDATE / LOCK IN SHARE MODE) and ``%s``
  placeholders are translated, since SQLite serialises writers anyway;
* Decimal parameters bind as exact text, as PyMySQL accepts them;
* the block commits on success and rolls back on any exception, exactly like
  db_session; close() is a no-op because the fixture owns the connection.
"""
import re
import sqlite3
from contextlib import contextmanager
from decimal import Decimal

# PyMySQL binds Decimal natively; keep its exact text in SQLite.
sqlite3.register_adapter(Decimal, str)

_LOCKS = re.compile(r'\s+(?:FOR\s+UPDATE(?:\s+(?:NOWAIT|SKIP\s+LOCKED))?|LOCK\s+IN\s+SHARE\s+MODE)\b', re.I)


def _sql(statement):
    return _LOCKS.sub('', statement).replace('%s', '?')


class Row(dict):
    """Dict row that also supports positional access like a tuple row."""

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


def _row(row):
    if row is None or isinstance(row, Row):
        return row
    if isinstance(row, sqlite3.Row):
        return Row(zip(row.keys(), tuple(row)))
    return row


def _params(params):
    if params is None:
        return ()
    return params if isinstance(params, dict) else tuple(params)


class Cursor:
    def __init__(self, cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._cursor.close()
        return False

    def __iter__(self):
        return (_row(row) for row in self._cursor)

    def execute(self, statement, params=()):
        self._cursor.execute(_sql(statement), _params(params))
        return self

    def executemany(self, statement, seq):
        self._cursor.executemany(_sql(statement), [_params(p) for p in seq])
        return self

    def fetchone(self):
        return _row(self._cursor.fetchone())

    def fetchall(self):
        return [_row(row) for row in self._cursor.fetchall()]

    def fetchmany(self, size=None):
        rows = self._cursor.fetchmany() if size is None else self._cursor.fetchmany(size)
        return [_row(row) for row in rows]

    def close(self):
        self._cursor.close()

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def description(self):
        return self._cursor.description


class Connection:
    def __init__(self, db):
        self._db = db

    def cursor(self, *args, **kwargs):
        return Cursor(self._db.cursor())

    def execute(self, statement, params=()):
        return Cursor(self._db.cursor()).execute(statement, params)

    def executemany(self, statement, seq):
        return Cursor(self._db.cursor()).executemany(statement, seq)

    def commit(self):
        self._db.commit()

    def rollback(self):
        self._db.rollback()

    def close(self):
        """The fixture owns the shared in-memory database."""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *exc):
        (self.rollback if exc_type else self.commit)()
        return False

    def __getattr__(self, name):
        return getattr(self._db, name)


@contextmanager
def transaction(db):
    connection = Connection(db)
    try:
        yield connection
        db.commit()
    except BaseException:
        db.rollback()
        raise
