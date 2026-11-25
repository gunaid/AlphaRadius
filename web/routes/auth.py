# -*- coding: utf-8 -*-
"""
ALPHA RADIUS Web - Authentication, Login, and Session Management Routes Module.
"""

import os
import sys
import json
import time
import datetime
import secrets
import logging

from flask import (
    Blueprint, render_template, request, jsonify, redirect,
    url_for, send_file, flash, session, current_app, Response
)

from database.db import (
    query_all, query_one, execute_write, execute_update, execute_many,
    log_audit, log_user_audit, DB_PATH
)
from core.config import (
    DB_TYPE, APP_NAME, APP_VERSION, APP_EDITION, APP_VERSION_FULL, APP_VERSION_BADGE,
    STORAGE_DIR, BACKUPS_DIR, UPLOADS_DIR, LOGS_DIR
)
from core.rate_limit import format_bytes, format_duration, build_mikrotik_rate_limit
from core.mikrotik_api import get_nas_status
from core.rbac import (
    get_current_manager, has_permission, require_permission,
    verify_manager_password, hash_manager_password, login_required
)
from web.decorators import require_role_or_permission

# Services imports
from services.subscriber_service import *
from services.voucher_service import *
from services.card_design_service import *
from services.reseller_service import *
from services.nas_service import *
from services.l2tp_service import *
from services.stats_service import *
from services.user_portal_service import *
from services.import_service import *
from services.quick_action_service import *
from services.backup_service import *
from services.backup_scheduler_service import *
from services.system_control_service import *
from services.manager_service import *
from services.license_guard_service import *
from services.system_update_service import *
from core.time_service import (
    sync_ntp_time, start_ntp_sync_worker, get_time_sync_status,
    get_configured_timezone_name, get_system_now, get_system_now_str
)

logger = logging.getLogger('auth_bp')

auth_bp = Blueprint('auth_bp', __name__)


@auth_bp.route('/health', endpoint="health_check")

def health_check():
    return jsonify({
        'status': 'healthy',
        'app': 'ALPHA RADIUS',
        'timestamp': datetime.datetime.now().isoformat()
    }), 200


@auth_bp.route('/login', methods=['GET', 'POST'], endpoint="login")

def login():
    if request.method == 'GET':
        if get_current_manager():
            return redirect(url_for('dashboard'))
        return render_template('login.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    remember = request.form.get('remember') == 'on'

    if not username or not password:
        flash('يرجى إدخال اسم المستخدم وكلمة المرور.', 'danger')
        return render_template('login.html'), 400

    manager = query_one('''
        SELECT m.*, r.name as role_name, r.code as role_code
        FROM wisp_managers m
        JOIN wisp_roles r ON m.role_id = r.id
        WHERE LOWER(m.username) = LOWER(?)
    ''', (username,))

    if not manager:
        log_audit(0, username, 'LOGIN_FAILED', 'auth', f'Failed login attempt for non-existing username [{username}]')
        flash('اسم المستخدم أو كلمة المرور غير صحيحة.', 'danger')
        return render_template('login.html'), 401

    if not manager.get('is_active'):
        log_audit(manager['id'], username, 'LOGIN_BLOCKED', 'auth', f'Deactivated account [{username}] attempted login')
        flash('عذراً، هذا الحساب معطل حالياً. يرجى مراجعة إدارة النظام.', 'danger')
        return render_template('login.html'), 403

    if not verify_manager_password(manager['password_hash'], password):
        log_audit(manager['id'], username, 'LOGIN_FAILED', 'auth', f'Invalid password for [{username}]')
        flash('اسم المستخدم أو كلمة المرور غير صحيحة.', 'danger')
        return render_template('login.html'), 401

    next_page = request.form.get('next') or request.args.get('next')
    from services import two_factor_service as tfa
    if tfa.needs_second_factor(manager['id'], request.cookies.get(tfa.DEVICE_COOKIE)):
        # Password is right but this browser is new: ask for the authenticator code.
        session.pop('admin_id', None)
        session['pending_2fa'] = {'manager_id': int(manager['id']), 'at': time.time(), 'attempts': 0,
                                  'next': next_page or ''}
        log_audit(manager['id'], username, 'LOGIN_2FA_REQUIRED', 'auth', f'New device for [{username}]; code requested')
        return redirect(url_for('login_verify'))
    return _complete_login(manager, next_page)


def _complete_login(manager, next_page=None, device_token=None):
    username = manager['username']
    session.permanent = True
    session.pop('pending_2fa', None)
    session['admin_id'] = manager['id']
    session['admin_username'] = manager['username']
    session['role_code'] = manager['role_code']
    session.pop('original_admin_id', None) # Clear any lingering impersonation

    execute_write('UPDATE wisp_managers SET last_login_at = ? WHERE id = ?',
                  (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), manager['id']))

    log_audit(manager['id'], username, 'LOGIN_SUCCESS', 'auth', f'Manager [{username}] ({manager["role_name"]}) logged in successfully')

    flash(f'مرحباً بك مجدداً، {manager["full_name"]}', 'success')
    if next_page and next_page.startswith('/') and not next_page.startswith('//') and not next_page.startswith('/login'):
        response = redirect(next_page)
    else:
        response = redirect(url_for('dashboard'))
    if device_token:
        from services import two_factor_service as tfa
        response.set_cookie(tfa.DEVICE_COOKIE, device_token, max_age=tfa.TRUST_DAYS * 86400, httponly=True,
                            secure=request.is_secure, samesite='Lax')
    return response


@auth_bp.route('/login/verify', methods=['GET', 'POST'], endpoint="login_verify")
def login_verify():
    """Second step of a login from a new device: the authenticator code."""
    from services import two_factor_service as tfa
    pending = session.get('pending_2fa')
    if not tfa.pending_valid(pending):
        session.pop('pending_2fa', None)
        flash('انتهت مهلة التحقق؛ سجّل الدخول مجددًا.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'GET':
        return render_template('login_verify.html')
    manager = query_one('''SELECT m.*, r.name as role_name, r.code as role_code FROM wisp_managers m
                           JOIN wisp_roles r ON m.role_id = r.id WHERE m.id = ?''', (pending['manager_id'],))
    if not manager or not manager.get('is_active'):
        session.pop('pending_2fa', None)
        return redirect(url_for('login'))
    if tfa.verify_code(manager['id'], request.form.get('code', '')):
        token = tfa.trust_device(manager['id'], request.headers.get('User-Agent', '')) \
            if request.form.get('trust') == 'on' else None
        log_audit(manager['id'], manager['username'], 'LOGIN_2FA_SUCCESS', 'auth',
                  'Authenticator code accepted' + ('; device trusted' if token else ''))
        return _complete_login(manager, pending.get('next'), token)
    pending['attempts'] = int(pending.get('attempts') or 0) + 1
    session['pending_2fa'] = pending
    log_audit(manager['id'], manager['username'], 'LOGIN_2FA_FAILED', 'auth', f"Wrong code (attempt {pending['attempts']})")
    if not tfa.pending_valid(pending):
        session.pop('pending_2fa', None)
        flash('محاولات كثيرة خاطئة؛ سجّل الدخول مجددًا.', 'danger')
        return redirect(url_for('login'))
    flash('الرمز غير صحيح.', 'danger')
    return render_template('login_verify.html'), 401


@auth_bp.route('/profile/security', methods=['GET'], endpoint="profile_security")
def profile_security():
    from services import two_factor_service as tfa
    manager = get_current_manager()
    if not manager:
        return redirect(url_for('login'))
    record = tfa.totp_record(manager['id'])
    setup = record if record and not int(record.get('enabled') or 0) else None
    return render_template('profile_security.html', enabled=tfa.is_enabled(manager['id']),
                           setup_secret=setup['secret_b32'] if setup else '',
                           setup_uri=tfa.provisioning_uri(setup['secret_b32'], manager['username']) if setup else '',
                           devices=tfa.devices(manager['id']), trust_days=tfa.TRUST_DAYS)


@auth_bp.route('/profile/security/<action>', methods=['POST'], endpoint="profile_security_action")
def profile_security_action(action):
    from services import two_factor_service as tfa
    manager = get_current_manager()
    if not manager:
        return redirect(url_for('login'))
    try:
        if action == 'setup':
            tfa.start_setup(manager['id'])
            flash('امسح الرمز بتطبيق المصادقة ثم أدخل الرمز الظاهر لتفعيل التحقق.', 'info')
        elif action == 'enable':
            tfa.enable(manager['id'], request.form.get('code', ''))
            log_audit(manager['id'], manager['username'], '2FA_ENABLED', 'auth', 'Authenticator enabled')
            flash('فُعّل التحقق بخطوتين؛ سيُطلب الرمز عند الدخول من جهاز جديد فقط.', 'success')
        elif action == 'disable':
            full = get_manager_by_id(manager['id'])
            if not verify_manager_password(full['password_hash'], request.form.get('password', '')):
                raise ValueError('كلمة المرور غير صحيحة.')
            tfa.disable(manager['id'])
            log_audit(manager['id'], manager['username'], '2FA_DISABLED', 'auth', 'Authenticator disabled')
            flash('أُوقف التحقق بخطوتين وحُذفت الأجهزة الموثوقة.', 'warning')
        elif action == 'forget-devices':
            count = tfa.forget_devices(manager['id'])
            log_audit(manager['id'], manager['username'], '2FA_DEVICES_FORGOTTEN', 'auth', f'{count} devices')
            flash('حُذفت الأجهزة الموثوقة؛ سيُطلب الرمز في الدخول التالي من أي جهاز.', 'info')
        else:
            flash('إجراء غير معروف.', 'danger')
    except ValueError as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('profile_security'))


@auth_bp.route('/logout', methods=['GET', 'POST'], endpoint="logout")

def logout():
    manager = get_current_manager()
    if manager:
        log_audit(manager['id'], manager['username'], 'LOGOUT', 'auth', f'Manager [{manager["username"]}] logged out')
    session.clear()
    flash('تم تسجيل الخروج بنجاح.', 'info')
    return redirect(url_for('login'))


@auth_bp.route('/profile/update', methods=['POST'], endpoint="profile_update")

def profile_update():
    manager = get_current_manager()
    if not manager:
        return jsonify({'success': False, 'message': 'يرجى تسجيل الدخول أولاً.'}), 401

    try:
        data = request.form if request.form else (request.get_json(silent=True) or {})
        full_name = data.get('full_name', '').strip()
        email = data.get('email', '').strip()
        phone = data.get('phone', '').strip()
        current_password = data.get('current_password', '').strip() or None
        new_password = data.get('new_password', '').strip() or None
        confirm_password = data.get('confirm_password', '').strip() or None

        if not full_name:
            return jsonify({'success': False, 'message': 'الاسم الكامل مطلوب.'}), 400

        if new_password:
            if new_password != confirm_password:
                return jsonify({'success': False, 'message': 'كلمة المرور الجديدة وتأكيدها غير متطابقين.'}), 400
            if len(new_password) < 4:
                return jsonify({'success': False, 'message': 'كلمة المرور يجب ألا تقل عن 4 أحرف.'}), 400

        update_manager_profile(
            manager_id=manager['id'],
            full_name=full_name,
            email=email,
            phone=phone,
            current_password=current_password,
            new_password=new_password
        )

        return jsonify({
            'success': True,
            'message': 'تم تحديث بيانات الملف الشخصي بنجاح.'
        })
    except ValueError as ve:
        return jsonify({'success': False, 'message': str(ve)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'حدث خطأ أثناء التحديث: {str(e)}'}), 500


@auth_bp.route('/managers/<int:manager_id>/impersonate', methods=['POST'], endpoint="impersonate_manager")

def impersonate_manager(manager_id):
    current = get_current_manager()
    if not current:
        return jsonify({'success': False, 'message': 'يرجى تسجيل الدخول أولاً.'}), 401

    # Super Admin Check: ID 1 or role superadmin or original_admin_id == 1
    original = get_manager_by_id(session['original_admin_id']) if session.get('original_admin_id') else current
    is_super = bool(original and original.get('is_active') and not original.get('is_deleted')
                    and (original.get('id') == 1 or original.get('role_code') == 'superadmin'))
    if not is_super:
        return jsonify({'success': False, 'message': 'عذراً، ميزة انتحال الشخصية متاحة فقط للمدير العام (Super Admin).'}), 403

    target = get_manager_by_id(manager_id)
    if not target:
        return jsonify({'success': False, 'message': 'حساب المدير أو الموزع المطلوب غير موجود.'}), 404

    if not target.get('is_active') or target.get('is_deleted'):
        return jsonify({'success': False, 'message': 'لا يمكن الدخول كحساب معطل.'}), 400

    # Save original admin id if not already set
    if not session.get('original_admin_id'):
        session['original_admin_id'] = current['id']

    session['admin_id'] = target['id']
    session['admin_username'] = target['username']
    session['role_code'] = target['role_code']

    log_audit(target['id'], current['username'], 'IMPERSONATE_START', 'security',
              f'Super Admin [{current["username"]}] impersonated manager [{target["username"]}] ({target["full_name"]})')

    return jsonify({
        'success': True,
        'message': f'أنت تتصفح الآن كـ: {target["full_name"]} ({target["role_name"]})',
        'redirect_url': url_for('dashboard')
    })


@auth_bp.route('/impersonate/exit', methods=['POST'], endpoint="impersonate_exit")

def impersonate_exit():
    original_id = session.get('original_admin_id')
    if not original_id:
        return jsonify(success=False, message='لا توجد جلسة انتحال للعودة منها.'), 403
    orig = get_manager_by_id(original_id)
    if not orig or not orig.get('is_active') or orig.get('is_deleted') or not (orig['id'] == 1 or orig.get('role_code') == 'superadmin'):
        session.clear()
        return redirect(url_for('login'))
    session.pop('original_admin_id', None)
    session['admin_id'] = orig['id']
    session['admin_username'] = orig['username']
    session['role_code'] = orig['role_code']
    session.pop('manager', None)
    session.pop('permissions', None)
    log_audit(orig['id'], orig['username'], 'IMPERSONATE_EXIT', 'security', 'Returned to verified original administrator')
    flash('تمت العودة إلى حساب المدير العام الأصلي بنجاح.', 'success')
    return redirect(url_for('managers_page'))


