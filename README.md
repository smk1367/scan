# Wireless Monitor Enterprise

نسخه‌ی بازطراحی‌شده‌ی سامانه مانیتورینگ لینک‌های رادیویی با تمرکز روی MikroTik، اسکن چندشهری، تاریخچه و RX/TX واقعی.

## تغییرات اصلی

- داشبورد اصلی فقط شهرها را نشان می‌دهد؛ IPها در صفحه‌ی اصلی لیست نمی‌شوند.
- با ورود به هر شهر، دستگاه‌های همان شهر نمایش داده می‌شوند.
- Full Scan: همه‌ی IPهای target ثبت می‌شوند، حتی `not_alive`، `blacklisted` و `failed`.
- تب `IPهای اسکن شده` برای دیدن تمام IPهای یک Scan و علت رد/خطا.
- برای هر شهر CIDR، SSH Port، SNMP Port، API Port، timeout و چند credential مستقل وجود دارد.
- RouterOS API فقط روی Plain TCP استفاده می‌شود. `API_USE_SSL` عمداً `0` است و 8729 استفاده نمی‌شود.
- MikroTik data path:
  - SNMP: System / CPU / RAM / Temperature / Uptime / IF-MIB traffic/status
  - RouterOS API: Wireless / SSID / Frequency / Radio / Registration / Interfaces / Queues / Firewall / PPPoE / Routes
  - SSH: fallback و سازگاری RouterOS قدیمی
- RX/TX ساختگی حذف شده است. برای Station، `signal-strength` به RX و `tx-signal-strength` به Peer TX نگاشت می‌شود و `tx-rate` / `rx-rate` جداگانه ذخیره می‌شوند.
- Radio Scan دستی ابتدا Plain RouterOS API را امتحان می‌کند و در صورت عدم وجود command با syntax صحیح SSH همان RouterOS را امتحان می‌کند.
- تاریخچه‌ی اسکن به صورت Snapshot ذخیره می‌شود و تغییرات فیلدبه‌فیلد در `device_changes` ثبت می‌شوند.
- retention پیش‌فرض 24 ساعت است و Full می‌تواند تاریخچه‌ی قدیمی را دستی حذف کند.
- Full Excel export با انتخاب 12 / 24 / 36 ساعت یا کل داده وجود دارد.
- Auto Backup در `/app/backups` ذخیره می‌شود و فاصله‌ی 12 / 24 / 36 ساعت از داشبورد قابل انتخاب است.
- Blacklist و Manual Radio ورود/خروجی Excel دارند.
- Manual Radio در تب اصلی و Wireless دستگاه قابل مشاهده است.
- Logout در داشبورد قرار دارد.

## نصب

```bash
cp .env.example .env
nano .env
docker compose build
docker compose up -d
```

پورت داشبورد: `5000`

پیش‌فرض RouterOS API: `8728` و بدون SSL.

### مثال تنظیم شهر

در مدیریت داشبورد، برای تهران می‌توانید مثلاً:

- CIDR: `172.17.240.0/20`
- SSH: `22`
- SNMP: `161`
- API: `8728`
- SSH credentials:

```json
[
  {"id":"admin1","username":"admin","password":"PASSWORD1"},
  {"id":"operator","username":"op","password":"PASSWORD2"}
]
```

Communityهای SNMP:

```json
["ngstehwl"]
```

برای شهری دیگر فقط همین مقادیر را با credential/portهای همان شهر وارد کنید.

## نکته RX/TX MikroTik

نمونه Station شما:

- RX / Signal: `-47 dBm`
- Peer TX Signal: `-29 dBm`
- TX Rate: `130Mbps-80MHz/2S/SGI`
- RX Rate: `175.5Mbps-80MHz/2S`
- TX CCQ: `34%`
- RX CCQ: `23%`
- SNR: `43 dB`
- Noise Floor: `-90 dBm`

این فیلدها در تب Wireless جداگانه نگه‌داری می‌شوند. در AP که فقط `registered-clients` و `overall-tx-ccq` برمی‌گرداند، مقدار RX/TX Peer اختراع نمی‌شود و فقط همان داده‌ی واقعی نمایش داده می‌شود.
# scan
