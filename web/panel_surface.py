"""Separate admin panel port (opt-in).

With ADMIN_PORT set (e.g. 43333) and different from PORT, the web service
listens on both ports (run.py) and every request is tagged by the port it
arrived on. The port comes from the listening socket (WSGI SERVER_PORT as set
by Waitress), never from Host or X-Forwarded-* headers, so a client cannot
reach the admin side by forging a header.

* admin port: the full system, exactly as before (admins can still preview
  the subscriber portal there);
* main port (PORT, behind Nginx on 80): subscriber self-service portal only.
  "/" opens the portal login; admin pages, admin login and admin APIs answer
  404 so the panel's existence is not advertised.

Without ADMIN_PORT (or with an invalid one) nothing changes: one port serves
everything. No database, license or configuration import happens here.
"""
import os

# Reachable on the subscriber port. /api/hotspot and the WhatsApp webhook are
# called by routers/gateways that know only the public address.
PORTAL_PREFIXES = ('/user/', '/static/', '/api/hotspot/')
PORTAL_PATHS = frozenset(('/user', '/favicon.ico', '/health', '/api/whatsapp/webhook'))
PORTAL_HOME = '/user/login'

NOT_FOUND_PAGE = ('<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8">'
                  '<meta name="viewport" content="width=device-width, initial-scale=1">'
                  '<title>404</title></head><body style="font-family:Tahoma,Arial,sans-serif;'
                  'text-align:center;padding:48px 16px;color:#334155">'
                  '<h1 style="font-size:40px;margin:0 0 8px">404</h1><p>الصفحة غير موجودة.</p>'
                  '<p><a href="/user/login">بوابة المشتركين</a></p></body></html>')


def _port(value):
    value = str(value or '').strip()
    if not value.isdigit():
        return None
    number = int(value)
    return number if 1 <= number <= 65535 else None


def admin_port(env=None):
    """The separate admin port, or None when the split is off."""
    env = os.environ if env is None else env
    admin = _port(env.get('ADMIN_PORT'))
    main = _port(env.get('PORT')) or 5090
    return admin if admin and admin != main else None


def surface(environ, admin):
    """'all' when the split is off, else 'admin' or 'portal' by listening port."""
    if not admin:
        return 'all'
    return 'admin' if str(environ.get('SERVER_PORT', '')) == str(admin) else 'portal'


def portal_allows(path):
    return path in PORTAL_PATHS or path.startswith(PORTAL_PREFIXES)


def install(app, admin=None):
    """Register the port guard as the app's first before_request handler."""
    from flask import g, redirect, request

    admin = admin_port() if admin is None else admin
    app.config['ADMIN_PORT'] = admin

    def panel_surface_guard():
        g.panel_surface = surface(request.environ, admin)
        if g.panel_surface != 'portal':
            return None
        if request.path == '/':
            return redirect(PORTAL_HOME)
        if portal_allows(request.path):
            return None
        return NOT_FOUND_PAGE, 404, {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store'}

    app.before_request_funcs.setdefault(None, []).insert(0, panel_surface_guard)

    @app.context_processor
    def panel_surface_context():
        return {'panel_surface': g.get('panel_surface', 'all'), 'admin_port': admin}

    return admin
