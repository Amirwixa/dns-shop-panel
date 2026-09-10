# 🚀 انتشار روی گیت‌هاب + نصب تک‌خطی (راهنمای قدم‌به‌قدم)

با این کار، نصب روی هر سرور اوبونتو فقط با **یک دستور** انجام می‌شود و آپدیت هم با اجرای دوباره همان دستور است.

---

## قدم ۱ — دانلود پروژه روی کامپیوتر خودت

فایل `dns-shop-panel.tar.gz` را از همین‌جا دانلود و باز کن (پوشه `dns-shop-panel`).

## قدم ۲ — ساخت ریپو در گیت‌هاب

1. برو به https://github.com/new
2. اسم ریپو مثلاً: `dns-shop-panel`
3. حتماً **Public** انتخاب کن ⚠️ (اگه Private باشد، دستور نصب روی سرور کار نمی‌کند چون دانلود بدون لاگین است)
4. **Add a README / .gitignore / license را تیک نزن** (خود پروژه همه را دارد)
5. Create repository → آدرس ریپو را کپی کن، مثلاً:
   ```
   https://github.com/MYNAME/dns-shop-panel.git
   ```

> 🔒 انتشار عمومی امن است: رمزها و دیتابیس فقط روی سرور ساخته می‌شوند و `.gitignore` نمی‌گذارد داخل گیت بروند.

## قدم ۳ — گذاشتن آدرس ریپو داخل فایل‌ها (۲ جای کوچک)

قبل از پوش، این ۲ فایل را ویرایش کن و `YOUR_USER/dns-shop-panel` را با آدرس واقعی ریپوت عوض کن:

1. **`install-remote.sh`** خط ~۱۳:
   ```bash
   REPO="${GITHUB_REPO:-MYNAME/dns-shop-panel}"
   ```
2. **`README.md`** بخش نصب تک‌خطی (اول فایل):
   ```bash
   bash <(curl -fsSL https://raw.githubusercontent.com/MYNAME/dns-shop-panel/main/install-remote.sh)
   ```

## قدم ۴ — پوش به گیت‌هاب

ترمینال (یا Git Bash در ویندوز) را داخل پوشه `dns-shop-panel` باز کن:

```bash
git init -b main
git add .
git commit -m "DNS Shop Panel v1.3"
git remote add origin https://github.com/MYNAME/dns-shop-panel.git
git push -u origin main
```

(اگه موقع push یوزر/پسورد خواست: پسورد همان **Personal Access Token** است نه رمز گیت‌هاب — از Settings → Developer settings → Tokens می‌سازی.)

## قدم ۵ — نصب روی سرور با یک دستور 🎉

حالا روی **هر سرور اوبونتویی** (با دسترسی root) فقط این را بزن:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MYNAME/dns-shop-panel/main/install-remote.sh)
```

- سرور تازه → نصب کامل خودکار
- سروری که پنل را دارد → **آپدیت خودکار** (کاربران و دیتا حفظ می‌شود)

### آپدیت‌های بعدی خودت

هر وقت کدی را عوض کردی:

```bash
git add . && git commit -m "update" && git push
```

بعد روی سرور همان دستور تک‌خطی را دوباره اجرا کن → خودش `update.sh` را می‌زند و سرویس‌ها را ری‌استارت می‌کند. ✅
