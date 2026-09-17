# QuicProbe

QuicProbe هو أداة تحليل أمنية مكتوبة بـ Pure Python، مخصصة لفحص مؤشرات QUIC/HTTP3 واكتشاف محاولات تسجيل الدخول الفاشلة في سجلات الأمان.

## نظرة عامة
تم بناء هذا المشروع كأداة تحليل أمنية خفيفة ومفيدة باستخدام مكتبات Python القياسية فقط. وهو مناسب للاستخدام التعليمي والدفاعي وأبحاث تحليل الشبكات والسجلات.

## المزايا
- فحص مؤشرات QUIC وHTTP/3
- تحليل سجلات الأمان لاكتشاف محاولات الدخول الفاشلة
- كشف عناوين IP المشبوهة بناءً على التكرار
- تصنيف أحداث أمنية متعددة: الدخول الفاشل، Firewall، هجمات Web، وفحص المنافذ
- حفظ عناوين IP الخاصة بكل نوع حدث وحساب الخطورة بناءً على نوع الحدث
- مؤشرات QUIC إضافية مثل ALPN وHTTP/3 وTLS و0-RTT وTransport Parameters
- واجهة أوامر سطرية سريعة
- تمييز مستويات الخطورة بالألوان في الطرفية
- إحصاءات للفحص متعدد المسارات: الملفات المفحوصة وملفات QUIC والدرجة الإجمالية
- تقرير HTML متجاوب يعرض ملخصًا بصريًا لمستوى الخطورة
- تنفيذ Pure Python بالكامل بدون مكتبات خارجية

## هيكل المشروع
- `quicprobe/` — الحزمة الرئيسية
- `quicprobe/cli.py` — واجهة سطر الأوامر
- `quicprobe/core/analyzer.py` — منطق التحليل
- `examples/` — ملفات عينات آمنة للتجربة
- `reports/` — التقارير الناتجة وتقارير العرض
- `scripts/` — ملفات الإعداد والتشغيل لـ Windows وKali/Linux
- `docs/` — وثائق التثبيت وبنية المشروع
- `tests/` — اختبارات تلقائية
- `pyproject.toml` — بيانات الحزمة وتسجيل أمر CLI

## التثبيت

### Windows

المتطلبات: Windows 10 أو أحدث، وPython 3.10 أو أحدث.

```powershell
scripts\setup_windows.bat
scripts\run_windows.bat --help
```

### Kali Linux

المتطلبات: Python 3.10 أو أحدث وحزمة `python3-venv`.

```bash
chmod +x scripts/setup_kali.sh scripts/run_kali.sh
./scripts/setup_kali.sh
./scripts/run_kali.sh --help
```

ملفات الإعداد تنشئ بيئة `.venv` محلية وتشغل الحزمة مباشرة من مجلد المشروع. لا تحتاج الأداة إلى إنترنت أو مكتبات تشغيل خارجية لأنها Pure Python وتعتمد على المكتبات القياسية فقط.

أو التشغيل مباشرة من مجلد المشروع:

```bash
python -m quicprobe --help
```

## الاستخدام

```bash
python -m quicprobe --help
python -m quicprobe --version
python -m quicprobe info
python -m quicprobe scan examples/sample_quic_log.txt --json
python -m quicprobe log examples/sample_security_log.txt --json
python -m quicprobe scan examples/sample_quic_log.txt examples --export reports/demo.html
python -m quicprobe --no-color scan examples/sample_quic_log.txt
```

استخدم `--no-color` عند تحويل المخرجات إلى ملف أو عند استخدام طرفية لا تدعم ألوان ANSI.

### فحص ملفات خارجية

تقبل الأداة المسارات الكاملة خارج مجلد المشروع، مثل ملفات سطح المكتب أو USB أو سجلات النظام:

```powershell
python -m quicprobe scan "C:\Users\Public\Downloads\traffic.log" --json
python -m quicprobe log "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" --export reports\external.html
```

في Kali/Linux:

```bash
python3 -m quicprobe log /var/log/auth.log --json
python3 -m quicprobe scan /media/usb/security-logs --export reports/external.html
```

عند تمرير مجلد، تفحص الأداة الملفات داخله والمجلدات الفرعية تلقائيًا. الأداة تقرأ الملفات فقط ولا تعدل أو تحذف الملفات الأصلية.

للتعليمات الخاصة بكل نظام راجع [`docs/INSTALL_WINDOWS.md`](docs/INSTALL_WINDOWS.md) و[`docs/INSTALL_KALI.md`](docs/INSTALL_KALI.md).

## أمثلة المخرجات

### فحص QUIC

```json
{
  "path": "C:\\Users\\example\\sample_quic_log.txt",
  "is_quic_likely": true,
  "score": 9,
  "markers_found": ["QUIC", "HTTP/3", "Connection ID", "UDP"],
  "summary": "QUIC-like indicators detected."
}
```

### تحليل سجل الأمان

```json
{
  "failed_login_attempts": 6,
  "suspicious_ips": ["10.0.0.7", "10.0.0.5"],
  "high_risk": true,
  "summary": "Repeated failed login attempts detected."
}
```

## ملاحظة مهمة
هذا المشروع مخصص للتحليل الدفاعي والتعليم، ولا يقوم بفك تشفير حركة QUIC المشفرة أو الفحص المتقدم لطبقات الشبكة دون بيانات حقيقية أو سياق إضافي.

## الترخيص
MIT
