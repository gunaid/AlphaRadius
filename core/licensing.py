# -*- coding: utf-8 -*-
"""
Client License Verification Engine:
Validates Ed25519 digital signatures, machine bindings, expiry dates, and subscriber limits.
"""

import os
import json
import base64
import datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from core.hardware_fingerprint import get_machine_id, get_instance_uuid

AMAN_LICENSE_AUTHORITY = "aman-alpha"

# The only trusted license authority: https://ls.amtik.online. Packages signed
# by any other key (including the pre-migration publisher key) are rejected.
AMAN_MASTER_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA3G3TqEFxe9EAcbTR1WyqTMHx/BxAqc6tMb14iJAnzdU=
-----END PUBLIC KEY-----"""

# Backwards-compatible name for extensions that imported the old constant.
EMBEDDED_PUBLIC_KEY = AMAN_MASTER_PUBLIC_KEY

TRUSTED_LICENSE_PUBLIC_KEYS = (
    (AMAN_LICENSE_AUTHORITY, AMAN_MASTER_PUBLIC_KEY),
)


def get_master_public_key_pem(authority=AMAN_LICENSE_AUTHORITY):
    """Return the immutable response/package key for a known authority.

    Only the Aman authority is trusted; unknown authorities fail closed.
    """
    for name, public_key in TRUSTED_LICENSE_PUBLIC_KEYS:
        if name == authority:
            return public_key
    raise ValueError("Unknown Alpha Radius license authority")


def identify_license_authority(package_dict):
    """Verify the exact package bytes and return the trusted signing authority."""
    if not isinstance(package_dict, dict) or not isinstance(package_dict.get('payload'), dict):
        return None
    signature_text = package_dict.get('signature')
    if not isinstance(signature_text, str):
        return None
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, TypeError):
        return None
    if len(signature) != 64:
        return None
    canonical_json = json.dumps(package_dict['payload'], sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    data_bytes = canonical_json.encode('utf-8')
    # Resolve every key through get_master_public_key_pem so the pinned roots
    # have a single lookup point (also used by isolated tests with fixture keys).
    for authority, _ in TRUSTED_LICENSE_PUBLIC_KEYS:
        try:
            public_pem = get_master_public_key_pem(authority)
            public_key = serialization.load_pem_public_key(public_pem.encode('utf-8'))
            public_key.verify(signature, data_bytes)
            return authority
        except InvalidSignature:
            continue
        except (TypeError, ValueError):
            return None
    return None

def decode_license_string(lic_input):
    """
    Parses a license file string or Base64 token into a Python dictionary.
    """
    if not lic_input or not isinstance(lic_input, str):
        return None, "مفتاح الترخيص فارغ أو غير صالح"
        
    lic_input = lic_input.strip()
    
    # Try as JSON directly
    if lic_input.startswith('{') and lic_input.endswith('}'):
        try:
            return json.loads(lic_input), None
        except Exception as e:
            return None, f"خطأ في قراءة ملف الترخيص (JSON غير صالح): {str(e)}"
            
    # Try as Base64 encoded JSON
    try:
        decoded_bytes = base64.b64decode(lic_input)
        decoded_str = decoded_bytes.decode('utf-8')
        return json.loads(decoded_str), None
    except Exception:
        return None, "تنسيق مفتاح الترخيص غير معروف (يجب أن يكون ملف .lic أو نص Base64 مشفر)"

def verify_license_package(package_dict, current_active_sessions=0, current_nas=0, current_subscribers=0):
    """
    Performs complete verification of a license package:
    1. Signature validity (Ed25519)
    2. Machine ID & Instance UUID matching
    3. Expiration date
    4. Limits compliance (Supports new max_active_sessions and legacy max_subscribers)
    """
    if not isinstance(package_dict, dict) or 'payload' not in package_dict or 'signature' not in package_dict:
        return False, "هيكل ملف الترخيص غير مكتمل", {}
        
    payload = package_dict['payload']
    # 1. Verify against the two immutable Alpha trust roots.  The matching key,
    # not a package-controlled field, determines the provider and migration path.
    authority = identify_license_authority(package_dict)
    if authority is None:
        return False, "فشل التحقق الأمني: التوقيع الرقمي غير صالح أو تم التعديل على بيانات الترخيص", {}
        
    # 2. Check Machine ID & Instance UUID Binding (Dual-Lock Anti-Clone)
    licensed_hw = payload.get('hardware_id', 'ANY').strip().upper()
    current_hw = get_machine_id().strip().upper()
    
    if licensed_hw not in ('ANY', '*', 'ALL', 'UNLOCKED', ''):
        clean_lic = licensed_hw.replace('-', '')
        clean_cur = current_hw.replace('-', '')
        if clean_lic != clean_cur:
            return False, f"هذا الترخيص مقفل على سيرفر آخر (بصمة الترخيص: {licensed_hw} - بصمة هذا الجهاز: {current_hw})", payload

    # 2b. Check Instance UUID (Prevent cloning on the same host)
    licensed_inst = payload.get('instance_id', 'ANY').strip().upper()
    current_inst = get_instance_uuid().strip().upper()
    if licensed_inst not in ('ANY', '*', 'ALL', 'UNLOCKED', ''):
        clean_lic_inst = licensed_inst.replace('-', '')
        clean_cur_inst = current_inst.replace('-', '')
        if clean_lic_inst != clean_cur_inst:
            return False, f"هذا الترخيص مخصص لمنظومة أخرى على نفس السيرفر (معرف الترخيص: {licensed_inst} - معرف هذه النسخة: {current_inst})", payload
            
    # 3. Check Expiry Date
    expires_at_str = payload.get('expires_at', '')
    is_lifetime = payload.get('is_lifetime', False)
    
    now = datetime.datetime.now(datetime.timezone.utc)
    days_left = 9999

    if type(is_lifetime) is not bool or (not is_lifetime and not expires_at_str):
        return False, 'تاريخ انتهاء الترخيص غير معرف', {}
    
    if not is_lifetime and expires_at_str:
        try:
            # Format: 2026-09-01T23:59:59Z
            exp_date = datetime.datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
            if exp_date.tzinfo is None:
                exp_date = exp_date.replace(tzinfo=datetime.timezone.utc)
            diff = exp_date - now
            days_left = diff.days
            
            if diff.total_seconds() < 0:
                # Expired
                return False, f"انتهت صلاحية هذا الترخيص بتاريخ ({expires_at_str[:10]})", payload
        except Exception as e:
            return False, f"خطأ في قراءة تاريخ انتهاء الترخيص: {str(e)}", payload
            
    # 4. Check Limits Compliance (Distinguish new active_sessions from legacy subscribers)
    limits = payload.get('limits', {})
    if not isinstance(limits, dict):
        return False, 'حدود الترخيص غير صالحة', {}
    for name in ('max_active_sessions','max_subscribers','max_nas','max_managers'):
        if name in limits and limits[name] is not None and (type(limits[name]) is not int or limits[name] < 0):
            return False, 'حدود الترخيص يجب أن تكون أعدادًا صحيحة غير سالبة', {}
    max_active_sessions = limits.get('max_active_sessions')
    max_subs = limits.get('max_subscribers')
    max_nas = limits.get('max_nas', 15)
    max_managers = limits.get('max_managers', 10)
    
    is_over_quota = False
    quota_reason = ""
    
    if max_active_sessions is not None:
        license_mode = 'active_sessions'
        max_active_int = int(max_active_sessions)
        if max_active_int < 0:
            return False, 'سعة الترخيص لا تقبل قيمة سالبة', payload
        if max_active_int > 0 and int(current_active_sessions) > max_active_int:
            is_over_quota = True
            quota_reason = f"عدد الجلسات المتصلة حالياً ({int(current_active_sessions):,}) يتجاوز سقف باقة الترخيص ({max_active_int:,})"
    elif max_subs is not None:
        license_mode = 'legacy_subscribers'
        max_subs_int = int(max_subs)
        if max_subs_int > 0 and int(current_subscribers) > max_subs_int:
            is_over_quota = True
            quota_reason = f"عدد المشتركين الحاليين ({int(current_subscribers):,}) يتجاوز سقف باقة الترخيص القديمة ({max_subs_int:,})"
    else:
        return False, 'بيانات سقف الترخيص غير معرفة في حزمة الترخيص', payload

    if max_nas and int(max_nas) > 0 and int(current_nas) > int(max_nas):
        is_over_quota = True
        nas_msg = f"عدد أجهزة الراوتر ({int(current_nas):,}) يتجاوز سقف باقة الترخيص ({int(max_nas):,})"
        quota_reason = f"{quota_reason} و {nas_msg}" if quota_reason else nas_msg

    info = {
        "license_id": payload.get('license_id'),
        "client_name": payload.get('client_name'),
        "plan_tier": payload.get('plan_tier', 'Enterprise'),
        "is_lifetime": is_lifetime,
        "expires_at": expires_at_str,
        "days_left": days_left,
        "license_mode": license_mode,
        "is_legacy_license": (license_mode == 'legacy_subscribers'),
        "max_active_sessions": int(max_active_sessions) if max_active_sessions is not None else None,
        "current_active_sessions": int(current_active_sessions),
        "max_subscribers": int(max_subs) if max_subs is not None else 0,
        "current_subscribers": int(current_subscribers),
        "max_nas": max_nas,
        "max_managers": max_managers,
        "features": payload.get('features', {}),
        "hardware_id": licensed_hw,
        "current_machine_id": current_hw,
        "is_over_quota": is_over_quota,
        "quota_reason": quota_reason,
        "license_authority": authority,
        "requires_heartbeat": authority == AMAN_LICENSE_AUTHORITY,
    }
    
    return True, "الترخيص معتمد وصالح وموثق رقمياً بنجاح", info

