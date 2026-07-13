# Lara3 — إصلاح موت الجلسة بعد ~10 دقائق (Session Death Fix)

## المشكلة
كانت الجلسة (صلاحيات kernel r/w + RemoteCall) تعمل 24 ساعة، ثم بعد تطوير الشيل
بدأت تموت بعد ~10 دقائق مع:

```
remote getpid() returned: 34
destroying remote call session...
remote call session destroyed
(ds) KRW ERROR  stage: setsockopt  reason: setsockopt returned -1 (errno=22)
```

## السبب الجذري
الـcommit `6487f58` ("socket primitive hardening") أدخل **مزلاجاً دائماً** `g_socket_broken`:
عند أول فشل — ولو عابر (transient) — يُضبط `g_socket_broken = true` **بلا أي مسار استرجاع**.
والشيل (Omega) ينفّذ آلاف عمليات kernel r/w، فإحصائياً خلال ~10 دقائق تصيب عمليةٌ واحدة
فشلاً عابراً → يُغلق المزلاج → `ds_is_ready()` ترجع `false` للأبد → تفقد كل الصلاحيات.

إضافة إلى ذلك:
- `handlebg()` كان يدمّر RemoteCall عند دخول الخلفية (قفل الشاشة/تبديل التطبيق).
- تسريب mutex في `early_kread` (مسار size>0x20 كان يرجع دون فك القفل → deadlock).
- دوال الكتابة العامة لم تكن مغلفة بـ @try/@catch رغم أنها قد ترمي استثناء.

## الإصلاحات

### 1) `lara/kexploit/darksword.m` — نموذج قابل للاسترجاع
- `g_socket_broken` أصبح حالة **عابرة تُشفى ذاتياً** عند أول عملية ناجحة (لم يعد دائماً).
- `set_target_kaddr`: **إعادة محاولة محدودة (6×)** مع backoff 1.5ms قبل إعلان التدهور.
- فحص عنوان kernel أولاً (رخيص)، ثم فحص حيوية الـfd، ثم setsockopt مع إعادة المحاولة.
- `ds_is_ready()` أصبح **فحصاً حيّاً** (`_validate_control_socket`) وليس مزلاجاً.
- **cooldown 250ms** بعد الفشل لمنع عواصف الاستثناءات في الحلقات الضيقة.
- **إصلاح تسريب mutex** في `early_kread` (كان deadlock محتمل).
- تغليف كل دوال القراءة/الكتابة العامة بـ `@try/@catch` + فحوص صلاحية.
- دوال جديدة: `ds_revive()` (استرجاع رخيص) و `ds_reset_socket_broken()`.

### 2) `lara/kexploit/darksword.h`
- تصدير `ds_revive()` و `ds_reset_socket_broken()`.

### 3) `lara/classes/laramgr.swift`
- `reviveKRW()`: استرجاع الجلسة دون إعادة exploit كامل.
- `reexploit()`: إعادة بناء الـprimitives عند موت الـfd فعلاً.

### 4) `lara/lara.swift` — `handlebg()`
- **عدم تدمير RemoteCall عند الخلفية افتراضياً** (هذا ما كان يقتل الجلسات الطويلة).
  قابل للتهيئة عبر `destroyRemoteCallOnBackground` (الافتراضي = إبقاء حيّة).

### 5) `lara/funcs/keepalive.swift` — تحصين
- معالجة المقاطعات (مكالمات/Siri/منبه) والاستئناف التلقائي.
- مراقبة تغيّر المسار وإعادة بناء الجلسة عند media-services reset.
- volume غير صفري (0.01) + WAV صامت 5 ثوانٍ + إعادة تشغيل تلقائي عند التوقف.

### 6) `lara/views/app/ContentView.swift`
- زر **"Revive KRW Session"** مع مؤشّر صحة؛ إن فشل الاسترجاع يعيد الـexploit تلقائياً.

### 7) حراس الشيل Omega — `OmegaBootstrap/OmegaExtendedF/OmegaExtendedG.swift`
- كانت تستخدم `guard !ds_socket_broken()` (المزلاج العابر) فتمنع الأوامر حتى بعد فشل عابر.
- بُدّلت إلى `guard ds_is_ready()` (فحص حي للـfd) — 7 مواضع — لتتوافق مع الشفاء الذاتي.

## النتيجة
- فشل عابر واحد **لم يعد يقتل الجلسة** (شفاء ذاتي + إعادة محاولة).
- الجلسة تبقى حيّة عند الخلفية (keepalive محصّن + عدم التدمير).
- مسار استرجاع يدوي/تلقائي بدل إعادة تشغيل التطبيق.

## Lara4 — إصلاحات إضافية (Session Stability Hardening)

### 8) `lara/kexploit/darksword.m` — إصلاحات حرجة
- **إصلاح mutex**: `pthread_mutex_lock` مفقود في `set_target_kaddr` أدى إلى unlock بدون lock.
- **إصلاح نجاح setsockopt**: `pthread_mutex_unlock` مفقود عند النجاح (return) أدى إلى deadlock.
- **Bounds checking**: `control_socket_idx + 1` بدون تحقق من حدود المصفوفة (`socket_ports_count`).
- ** wired_mapping fix**: `surface_munlock` على `wired_mapping` غير مهيأ في non-A18.

### 9) `lara/lara.swift` — إصلاحات Timer و Error
- **Timer lifecycle**: `startHealthCheckTimer` يُستدعى فقط عند `dsready = true`.
- **Timer invalidate**: `stopHealthCheckTimer` عند الخلفية/خروج الـ exploit.
- **@retroactive Error**: إصلاح التوافق مع Swift 6.

### 10) `lara/classes/laramgr.swift` — إصلاحات
- **ytProc**: إزالة initialization مبكر غير ضروري لـ `RemoteCall`.
- **Encoding**: إصلاح مشكلة ترميز UTF-8 في التعليقات.

### 11) `lara/classes/OmegaBootstrap.swift` — أوامر جديدة
- **أمر `health`**: يعرض درجة صحة الجلسة (0-100) من `ds_session_health_score()`.
- **أمر `memstats`**: يعرض إحصائيات عمليات الذاكرة من `MemoryOperationTracker`.

### 12) `.github/workflows/build.yml` — إصلاح CI/CD
- **macos-latest**: تغيير `macos-15` إلى `macos-latest` (الـ runner المتاح).

### 13) `lara/classes/MemorySafetyManager.swift` — تحسينات
- **KernelAddressValidator**: تحسين التحقق من عناوين kernel مع دعم arm64.
- **MemoryOperationTracker**: تتبع نسبة النجاح/الفشل مع throttling تلقائي.
- **SafeKRW**: wrapper آمن حول عمليات KRW مع فحوصات صلاحية.

## ملاحظة
هذا exploit قائم على UAF؛ الاستقرار المطلق 100% غير ممكن نظرياً، لكن هذه الإصلاحات
تزيل سبب الموت المبكر المُدخَل أثناء تطوير الشيل وتعيد سلوك "الاستقرار الطويل".
