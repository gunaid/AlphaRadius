#!/bin/bash
# ==============================================================================
# 🚀 ALPHA RADIUS - التشغيل التلقائي عند أول إقلاع للنظام (First Boot Wizard)
# ==============================================================================

if [ -f /etc/alpha_radius_configured ]; then
    exit 0
fi

# تشغيل أداة alphaip تفاعلياً على الشاشة الرئيسية (tty1)
/usr/local/bin/alphaip

# وسم النظام بأنه تم ضبطه بنجاح لعدم تكرار الإطلاق
touch /etc/alpha_radius_configured
