# قوالب واتساب: أسماء الأعمدة الفعلية (26 نوفمبر 2026)

## الخلل

جدول `wisp_whatsapp_templates` في `database/schema_mysql.sql` و`database/schema_healer.py` أعمدته `template_key` و`message_body` و`is_active`. أما `services/whatsapp_service.py` فكان يستعلم بأسماء غير موجودة: `event_key` و`template_text` و`is_enabled`. الخلل موجود منذ الاستيراد الأول، وكان موجودًا أيضًا على الحزمة القديمة في 192.168.33.10 (الجدول هناك بالأعمدة نفسها وبلا صفوف).

ظهر في سجل Web على التثبيت الجديد بهذا النص: `Unknown column 'event_key' in 'WHERE'` و`Error seeding WhatsApp default data`.

أثره:
- رد البوت الافتراضي (قائمة الترحيب) يستدعي `get_template_by_key('welcome_menu')`، فيرمي الخطأ وتفشل معالجة الرسالة كلها؛ أي رسالة لا تطابق أمرًا محددًا لا يصلها رد.
- كل إرسال أو استقبال، ومنه [تنبيهات النظام عبر واتساب](SYSTEM_ALERTS_TELEGRAM_WHATSAPP_20261125.md)، يستدعي `get_whatsapp_settings()`، فتحاول البذر وتفشل بعد تشغيل `heal_database_schema()` مرتين (`database/db.py`).
- صفحة القوالب فارغة دائمًا والتعديل لا يُحفظ.
- دوال الإشعار الآلي (`notify_voucher_issued` و`notify_quota_warning` و`notify_wallet_recharge`) كانت ستفشل بالطريقة نفسها؛ لا يستدعيها أي مسار حاليًا.

## الإصلاح (كود فقط، بلا ترحيل للقاعدة)

- القراءة عبر `_TEMPLATE_SELECT` تسمّي الأعمدة الفعلية بالأسماء التي تستخدمها الصفحة والكود: `template_key AS event_key` و`message_body AS template_text` و`is_active AS is_enabled`. البحث بـ`template_key`.
- البذر والحفظ (`save_template`) يكتبان في `template_key` و`message_body` و`is_active`.
- البذر مرة واحدة لكل عملية Web. إن فشل لا يُعاد قبل 300 ثانية، بدل إعادته مع كل رسالة. تعديلات المستخدم على القوالب لا تُستبدل لأن البذر يضيف المفقود فقط.
- `get_template_by_key` يبذر أولًا، فيعمل الرد الافتراضي حتى لو لم تُفتح صفحة واتساب قبله.

## الفحوص

- `tests/test_whatsapp_templates.py` (معزول، 5): الخدمة الفعلية على جدول SQLite بالأعمدة نفسها، فيها البذر والقراءة والحفظ، والبذر مرة واحدة مع حفظ التعديلات، وعدم إعادة البذر الفاشل مع كل استدعاء، وتطابق أعمدة `schema_mysql.sql` و`schema_healer.py` مع ما تستخدمه الخدمة. فشل 4 منها على الكود السابق.
- الاستعلام الجديد قُبل على MariaDB الفعلية (`EXPLAIN`، قراءة فقط).
- نجحت `tests.test_alert_dispatch` و`tests.test_license_feature_policy` مع الاختبارات الجديدة (26) بـ Python صورة Web.
- لم يُختبر إرسال أو استقبال فعلي عبر بوابة واتساب.
