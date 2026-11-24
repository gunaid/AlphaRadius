# عقد خادم التراخيص — ما يجب أن ينفذه ls.amtik.online

هذه الوثيقة مستخرجة من كود العميل الحالي، وهي المرجع لأي خادم تراخيص يخدم نسخ ALPHA RADIUS. العميل يرفض أي رد لا يطابقها حرفيًا.
مصادر العميل: `core/licensing.py` و`core/license_protocol.py` و`services/license_guard_service.py` و`core/hardware_fingerprint.py` و`core/license_feature_policy.py`.
مرجع تنفيذ جزئي للخادم: `deploy/license-server/core/heartbeat_security.py` و`instance_enrollment.py`.

## 1. المفاتيح والترميز

- مفتاح الناشر (master) زوج **Ed25519**. المفتاح الخاص يبقى في الخادم فقط.
- المفتاح العام يُضمَّن في العميل بصيغة PEM (SubjectPublicKeyInfo) داخل `AMAN_MASTER_PUBLIC_KEY` في `core/licensing.py`. أي تغيير للمفتاح يتطلب إصدار عميل جديد.
- العميل يثق أيضًا بمفتاح قديم `LEGACY_MASTER_PUBLIC_KEY` للتراخيص الصادرة قبل الانتقال. مصدر الترخيص يُحدَّد من التوقيع نفسه، لا من حقل داخل الحزمة. التفاصيل في [ALPHA_LICENSE_PROVIDER_MIGRATION](ALPHA_LICENSE_PROVIDER_MIGRATION.md).
- المفتاح نفسه يوقّع **ملفات الترخيص** و**ردود النبضات**.
- التوقيع دائمًا على الصيغة القانونية للـ JSON:
  ```python
  json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
  ```
- التوقيعات والمفاتيح الخام بترميز Base64 القياسي (ليس urlsafe).

## 2. ملف الترخيص (license package)

```json
{
  "payload": {
    "license_id": "LIC-2026-0001",
    "client_name": "اسم العميل",
    "plan_tier": "Enterprise",
    "hardware_id": "ANY",
    "instance_id": "ANY",
    "issued_at": "2026-11-24T00:00:00Z",
    "expires_at": "2027-11-24T23:59:59Z",
    "is_lifetime": false,
    "limits": {
      "max_active_sessions": 500,
      "max_nas": 15,
      "max_managers": 10
    },
    "features": { "user_portal": true, "whatsapp_gateway": false }
  },
  "signature": "<Base64 Ed25519 over canonical(payload)>"
}
```

قواعد يفرضها العميل:
- `is_lifetime` قيمة منطقية حقيقية (bool). إذا كانت `false` فـ `expires_at` إلزامي بصيغة ISO‑8601، ويقبل اللاحقة `Z`.
- `hardware_id` و`instance_id` إما قيمة ربط، أو `ANY`/`*`/`ALL`/`UNLOCKED`/فارغ لعدم الربط. المقارنة غير حساسة لحالة الأحرف وتتجاهل `-`.
  - صيغة بصمة الجهاز الحالية: `MAX-XXXX-XXXX-XXXX-XXXX`.
  - صيغة معرف النسخة: `INST-XXXXXXXXXXXX` أو أي نص ≥ 8 أحرف من متغير `INSTANCE_UUID`.
- `limits`: كل قيمة عدد صحيح ≥ 0 (ليس float أو نص).
  - يجب وجود `max_active_sessions` (الوضع الحديث)، أو `max_subscribers` للتراخيص القديمة. بدونهما يُرفض الترخيص.
  - القيمة `0` تعني بلا سقف.
  - القيم الافتراضية عند الغياب: `max_nas=15` و`max_managers=10`.
- `features`: المفاتيح المسموحة فقط:
  `user_portal automation_rules gis_map autoheal accounting_archiver radius_simulator traffic_analytics api_access white_label whatsapp_gateway vpn_tunnels loyalty_rewards card_designer quick_cards reseller_management reseller_wallets sales_reports invoice_management userman_import data_import hotspot_designer portal_registration portal_advance`.
  - الميزة الغائبة تعتبر مفعّلة؛ `false` يعطّلها.
  - تبعيات: `reseller_wallets` تحتاج `reseller_management`، و`portal_registration`/`portal_advance` تحتاجان `user_portal`.
- التسليم للمستخدم: ملف `.lic` يحتوي JSON أعلاه، أو نفس JSON مشفّرًا Base64 ككود يُلصق.

### ملف التفعيل الأول

عند تنزيل الملف أو نسخ الكود من لوحة الخادم أضف حقلًا على المستوى الأعلى، **خارج `payload` وخارج التوقيع**:
```json
{ "payload": {...}, "signature": "...", "enrollment_token": "<سر عشوائي 32–128 حرفًا>" }
```
- الرمز للاستخدام مرة واحدة، صالح 24 ساعة.
- يخزن الخادم **بصمته SHA‑256 فقط** مربوطة بـ `license_id`.
- العميل يحذفه قبل حفظ الترخيص.

## 3. نقطة النبضات والتفعيل

`POST https://ls.amtik.online/api/v1/heartbeat/ping`

- HTTPS إلزامي، وبلا أي إعادة توجيه (العميل يرفض 301/302).
- مهلة العميل 6 ثوانٍ، وحجم الرد ≤ 1 MB.
- الترويسات: `Content-Type: application/json`، و`User-Agent: ALPHA-RADIUS-License/2.0`.
- عنوان الخادم في العميل: `MASTER_LICENSE_SERVER_URL`، والافتراضي `https://ls.amtik.online`.
- التراخيص الموقّعة بالمفتاح القديم لا تتصل بهذه النقطة إطلاقًا؛ تعمل بالتحقق المحلي فقط.

### جسم الطلب

```json
{
  "payload": {
    "license_id": "LIC-2026-0001",
    "hardware_id": "MAX-78FA-41B0-9A22-E10C",
    "instance_uuid": "INST-C89B104AF210",
    "app_version": "v2.7.1-…",
    "subscribers_count": 120,
    "nas_count": 3,
    "current_active_sessions": 80,
    "active_sessions_count": 80,
    "max_active_sessions": 500,
    "license_mode": "active_sessions",
    "system_uptime": "Online",
    "enrollment_token": "…",
    "request_nonce": "<48 hex>",
    "request_epoch": 1795000000
  },
  "signature": "<Base64 Ed25519 بمفتاح النسخة over canonical(payload)>",
  "public_key": "<Base64 لمفتاح النسخة العام الخام 32 بايت>"
}
```
- `system_uptime` قيمته `"Activation"` عند التفعيل، و`"Online"` في النبضات الدورية.
- `enrollment_token` موجود فقط في طلب التفعيل الأول.
- `current_active_sessions` قد تكون `null` إذا تعذرت القراءة.
- النبضة تُرسل كل 5 دقائق، مع 3 محاولات بفاصل 3 ثوانٍ.

### تحقق الخادم من الطلب (بالترتيب، في معاملة واحدة)

1. `request_nonce` نص طوله 48، و`request_epoch` عدد صحيح، و`|now - request_epoch| ≤ 120`. غير ذلك → 401.
2. إذا كان لـ `instance_uuid` مفتاح مسجل:
   - يجب أن يساوي `public_key` المرسل، وإلا → `401 {"error":"enrollment_key_mismatch"}`.
   - **لا يُستبدل المفتاح تلقائيًا أبدًا.**
3. تحقق من التوقيع بالمفتاح المسجل، أو بالمفتاح المرسل إن لم يوجد. فشل التوقيع → 401.
4. إن لم يوجد مفتاح مسجل، فهذا اعتماد أول ويحتاج `enrollment_token` صالحًا:
   - الرمز غائب → `enrollment_required`.
   - غير مطابق للترخيص أو مستهلك → `enrollment_token_invalid`.
   - منتهٍ → `enrollment_token_expired`.
   - الترخيص غير `active` أو منتهٍ → `enrollment_license_unavailable`.
   - الجهاز أو النسخة لا يطابق ربط الترخيص → `enrollment_binding_mismatch`.
   - IP أو بصمة أو نسخة في القائمة السوداء، أو النسخة موقوفة → `enrollment_blocked`.
   - تجاوز حد النسخ `max_instances` → `enrollment_instance_limit`.
   - عند النجاح: سجّل المفتاح، واحجز النسخة للترخيص، واستهلك الرمز، وسجّل التدقيق.
5. سجّل `(instance_uuid, request_nonce)` ورفض التكرار؛ احتفظ بها 300 ثانية على الأقل.

### أخطاء المصادقة

HTTP **401** بجسم JSON: `{"error": "<code>"}`. القيم المسموحة فقط هي الثمانية أعلاه.
العميل لا يعتبر 401 إلغاءً للترخيص ولا يغيّر حالته المحلية.

### الرد الناجح — HTTP 200 دائمًا وموقّع

أي قرار ترخيص يُرسل كـ **HTTP 200**، حتى الإلغاء والتعليق. العميل لا يقرأ جسم 403 أو 5xx ويعتبرها تعذّر اتصال.

```json
{
  "payload": {
    "license_id": "<نسخ حرفي من الطلب>",
    "hardware_id": "<نسخ حرفي من الطلب>",
    "instance_uuid": "<نسخ حرفي من الطلب>",
    "request_nonce": "<نسخ حرفي من الطلب>",
    "request_hash": "<sha256 hex لـ canonical(payload الطلب كاملًا)>",
    "issued_epoch": 1795000000,
    "expires_epoch": 1795000090,
    "valid": true,
    "status": "active",
    "remote_action": null,
    "remote_payload": null
  },
  "signature": "<Base64 Ed25519 بمفتاح الناشر over canonical(payload)>"
}
```

شروط يرفض العميل الرد بدونها:
- الحقول الأربعة الأولى تساوي قيم الطلب حرفيًا.
- `request_hash` محسوب على payload الطلب كما وصل، شاملًا `request_nonce` و`request_epoch` و`enrollment_token`.
- `issued_epoch` و`expires_epoch` أرقام. يجب أن يكون `issued ≤ now+30` و`expires > now` و`0 < expires-issued ≤ 120`. المقترح 90 ثانية.
- `status` واحد من: `active` `over_quota` `revoked` `suspended` `blacklisted` `hwid_mismatch` `unlicensed` `expired` `instance_limit` `error`.
- `valid == true` إذا وفقط إذا كانت `status` تساوي `active` أو `over_quota`.

### كيف يتصرف العميل بحسب الرد

| الرد | أثره على النسخة |
|---|---|
| `active` / `over_quota` | يحدّث آخر نبضة ويلغي فترة السماح. |
| `suspended` أو `remote_action:"suspend"` | تعليق الترخيص محليًا. |
| `revoked` / `blacklisted`، أو `remote_action:"revoke"` | حظر دائم محليًا (قائمة الحظر). يُرفع عند أول رد `active` لاحق. |
| `expired` | حالة محلية `expired`؛ تُرفع عند أول رد `active` لاحق. |
| `hwid_mismatch` / `unlicensed` / `error`، أو `remote_action:"unlicensed"`، أو `valid:false` | حالة محلية `unlicensed` دون حظر دائم؛ تُرفع عند أول رد `active` لاحق. |
| `instance_limit` | حالة محلية `instance_limit` مع رسالة بلوغ حد النسخ. |
| تعذر الاتصال | بعد ساعة تنبيه، وبعد **24 ساعة** قفل `grace_expired`. |

النبضة تُرسل حتى لو كانت الحزمة المحلية منتهية أو غير مطابقة للربط، ما دام توقيعها من مفتاح الخادم الحالي؛ هكذا يصل التجديد عن بعد إلى ترخيص منتهٍ. الحزمة ذات التوقيع غير الموثوق لا تُرسل نبضة.

**تحديث الترخيص عن بعد (OTA):** أرسل في `remote_payload` (أو `license_token`) ملف ترخيص كاملًا كنص JSON أو Base64، موقعًا بمفتاح الناشر.
- يُطبّق إذا كان `remote_action:"sync_license"`، أو إذا اختلف توقيعه عن المحفوظ.
- يُستخدم لتمديد المدة وتغيير السعة والميزات.

## 4. ما تحتاجه لوحة الخادم (حد أدنى)

- **التراخيص:** إنشاء وتعديل، مع الربط بالجهاز/النسخة، والمدة، والحدود، والميزات، و`max_instances`.
  - توقيع الحزمة.
  - تنزيل ملف `.lic` أو نسخ كود Base64 مع رمز تفعيل جديد. هذا الطلب POST محمي بـ CSRF، وبرد `Cache-Control: no-store`.
- **الحالة:** تعليق، إلغاء، إعادة تفعيل.
- **النسخ:** عرض النسخ المعتمدة ومفاتيحها وآخر نبضة وعداداتها، مع إيقاف نسخة وإعادة اعتماد مفتاح يدويًا.
- **القائمة السوداء:** IP / بصمة جهاز / معرف نسخة.
- **سجل تدقيق** لكل عملية.
- قاعدة بيانات بنسخ احتياطي. المفتاح الخاص خارج قاعدة البيانات وخارج Git، بصلاحيات 600.

## 5. فحص القبول

1. ترخيص صالح + ملف تفعيل → التفعيل ينجح من لوحة النسخة، ويظهر «مرخص ومفعل بالكامل».
2. إعادة استخدام نفس ملف التفعيل على نسخة أخرى → `enrollment_token_invalid`.
3. تعليق الترخيص من اللوحة → خلال 5 دقائق تظهر النسخة «معلق».
4. تعديل حدود الترخيص مع `sync_license` → تتحدث السعة في النسخة دون إعادة تفعيل.
5. إعادة إرسال نفس الطلب (nonce مكرر) → 401.
6. رد غير موقع أو بإعادة توجيه أو HTTP → يرفضه العميل.

يمكن اختبار البروتوكول مباشرة بـ `core/license_protocol.py:exchange` من مستودع العميل.
