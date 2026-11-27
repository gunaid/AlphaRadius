# تطابق سر فحص RADIUS بين Web وCore (26 نوفمبر 2026)

## الخلل

`deploy/local/build_and_start.sh` يكتب في `.env` قيمة عشوائية `RADIUS_HEALTH_SECRET` عند أول تثبيت. حاوية Web تفحص RADIUS بهذه القيمة (`services/health_probe_service.py`)، لكن compose لم يكن يمررها إلى Core، فكان عميل `web_container` في `clients.conf` يأخذ `RADIUS_SECRET_DEFAULT`.

النتيجة على أول تثبيت بالسكربت (192.168.33.10، 26 نوفمبر): سجل Core كل دقيقة يحتوي `invalid Message-Authenticator! (Shared secret is incorrect.) (from client web_container)`، ويظهر في Web تنبيه `RADIUS_UNRESPONSIVE` كاذب. هذا التنبيه سيصل إلى Telegram وWhatsApp عند تفعيل [تنبيهات النظام](SYSTEM_ALERTS_TELEGRAM_WHATSAPP_20261125.md). مصادقة الراوترات غير متأثرة لأنها تستخدم أسرار NAS من قاعدة البيانات.

## الإصلاح

- `docker/freeradius/entrypoint.sh`: عميل `web_container` يأخذ `RADIUS_WEB_CLIENT_SECRET`، وإن لم يُضبط يعود إلى `RADIUS_SECRET_DEFAULT` كما كان. عميلا `localhost` يبقيان على `RADIUS_SECRET_DEFAULT`، لأن فحص صحة الحاوية نفسه (`radtest ... max123`) يعتمد عليه.
- `docker-compose.production.yml` و`docker-compose.yml`: خدمة `freeradius` تأخذ `RADIUS_WEB_CLIENT_SECRET: ${RADIUS_HEALTH_SECRET:-max123}`، أي القيمة والافتراضي نفسيهما اللذين تأخذهما Web.
- التثبيت الذي لا يضبط `RADIUS_HEALTH_SECRET` لا يتغير؛ الطرفان يبقيان على `max123`.

## التطبيق على خادم قائم

يلزم إعادة إنشاء Core بالصورة الجديدة وملف compose الجديد. أسهل طريق إعادة تشغيل `sudo bash deploy/local/build_and_start.sh` من نسخة المصدر المحدثة. صورة Web تُبنى من الذاكرة المؤقتة دون إعادة ترجمة، لأن الملفات المعدلة ليست ضمن مدخلاتها. السكربت لا يلمس `.env` أو قاعدة البيانات.

## الفحوص

- `tests/test_radius_health_secret.py` (معزول، 3): يشغّل جزء `clients.conf` من entrypoint بـ bash في مجلد مؤقت ويتأكد أن `web_container` يأخذ سر الفحص و`localhost` يبقى على الافتراضي، والرجوع إلى الافتراضي عند غياب المتغير، وأن ملفي compose يمرران القيمة نفسها إلى Core وWeb. يفشل على entrypoint السابق.
- نجحت أيضًا `tests.test_realm_speed.EntrypointTests` و`tests.test_runtime_distribution`.
- على 192.168.33.10 بعد إعادة تشغيل السكربت (صور `local-202611260429`): الخدمات الخمس healthy، ولا رسالة `Shared secret is incorrect` في Core ولا `RADIUS_UNRESPONSIVE` في Web خلال دقيقتين. سر `web_container` في Core يساوي سر فحص Web، و`localhost` بقي على الافتراضي.

## ملاحظات من التحديث نفسه على 192.168.33.10

- الخادم كان يشغّل الحزمة القديمة `/opt/max-radius`. شبكتها `172.18.0.0/16` هي شبكة الحزمة الجديدة نفسها، فإيقاف الحاويات لا يكفي؛ يلزم `docker compose -p max-radius ... down`، وهو لا يحذف وحدة التخزين.
- السكربت ينشئ قاعدة جديدة فارغة ولا ينقل بيانات `max-radius_mariadb_data`. اختار المستخدم بداية نظيفة؛ القاعدة القديمة ونسخة dump منها بقيتا على الخادم.
- انقطاع الاتصال بـ PyPI أفشل أول بناء لـ Web. بناء مسبق بمستخدم في مجموعة docker، دون مفتاح التوقيع، يخزن كل الطبقات حتى خطوة التوقيع، فيصبح تشغيل السكربت بـ sudo قصيرًا. استغرق التنزيل والترجمة نحو 40 دقيقة على هذا الخادم.
- انسخ المصدر إلى الخادم من Windows بـ `git -c core.autocrlf=false archive`. الأرشيف العادي مع `core.autocrlf=true` يحوّل الملفات المخزنة بـ LF إلى CRLF، فتُبنى الصور من نص مختلف عن المستودع؛ وهذا ما حدث في أول تثبيت ثم أُعيد البناء. بعض الملفات مخزنة أصلًا بـ CRLF في المستودع (مثل `queries.conf` و`options.xl2tpd`)، وهذا طبيعي.
- في أول تشغيل ظهرت أخطاء «جدول غير موجود» في Web وCore قبل اكتمال الترحيل، ثم توقفت؛ الجداول موجودة (99).
