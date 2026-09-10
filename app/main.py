# DNS Shop Panel - Web Panel (Flask)
import os
import re
import time
import secrets
import threading
import ipaddress
from functools import wraps
from datetime import datetime
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, send_file

from . import database as db
from . import firewall as fw
from . import diag as dg

APP_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(APP_DIR)
DATA_DIR = os.path.dirname(db.DB_PATH)


def _persistent_secret_key() -> str:
    """A random secret key is required for session cookies to be secure.
    If PANEL_SECRET is set explicitly (recommended for multi-process/systemd
    deployments), use it. Otherwise generate one ONCE and store it next to
    the database so it survives restarts (a changing key would silently log
    every admin out on every restart, and a time.time()-based fallback is
    predictable)."""
    env = os.environ.get("PANEL_SECRET")
    if env:
        return env
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, "secret.key")
    try:
        with open(path, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key
    except OSError:
        pass
    key = secrets.token_hex(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key)
    except FileExistsError:
        with open(path, "r", encoding="utf-8") as f:
            key = f.read().strip() or key
    except OSError:
        pass
    return key


app = Flask(__name__, template_folder=os.path.join(APP_DIR, "templates"),
            static_folder=os.path.join(APP_DIR, "static"))
app.secret_key = _persistent_secret_key()
app.config["JSON_AS_ASCII"] = False
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Panel is served over plain HTTP by default (see README); only mark the
    # cookie Secure when we know we're behind TLS/HTTPS, otherwise the
    # browser would silently drop it and nobody could log in.
    SESSION_COOKIE_SECURE=os.environ.get("PANEL_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=int(os.environ.get("SESSION_LIFETIME_SEC", "86400")),
)

START_TIME = time.time()


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


# ---------- login brute-force protection ----------
_LOGIN_ATTEMPTS = {}  # key(ip or ip+username) -> [failure_timestamps]
_LOGIN_LOCK = threading.Lock()
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW_SEC = 300      # count failures within this window
LOGIN_LOCKOUT_SEC = 300     # lock the key out for this long once tripped


def _login_key(ip, username):
    return f"{ip}:{username.lower()}"


def _login_blocked(ip, username):
    key = _login_key(ip, username)
    now = time.time()
    with _LOGIN_LOCK:
        fails = [t for t in _LOGIN_ATTEMPTS.get(key, []) if now - t < LOGIN_WINDOW_SEC]
        _LOGIN_ATTEMPTS[key] = fails
        if len(fails) >= LOGIN_MAX_FAILS:
            return int(LOGIN_LOCKOUT_SEC - (now - fails[-1]))
    return 0


def _login_record_failure(ip, username):
    key = _login_key(ip, username)
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.setdefault(key, []).append(time.time())


def _login_clear(ip, username):
    key = _login_key(ip, username)
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.pop(key, None)


# ---------- helpers ----------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "unauthorized"}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except Exception:
        return False


def valid_domain(d: str) -> bool:
    d = d.strip().lower().rstrip(".")
    if len(d) > 253 or len(d) < 3:
        return False
    return re.match(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$", d) is not None


def _link_base() -> str:
    """Public base URL used for per-user self-service links."""
    try:
        s = db.get_all_settings()
        host = (s.get("server_ip") or "").strip()
        port = (s.get("panel_port") or "8080").strip() or "8080"
        if host:
            return f"http://{host}:{port}"
        return request.host_url.rstrip("/")
    except Exception:
        return ""


def _with_link(u):
    if not u:
        return u
    base = _link_base()
    u["link"] = f"{base}/u/{u['token']}" if u.get("token") and base else ""
    return u


def _with_links(users):
    base = _link_base()
    for u in users:
        u["link"] = f"{base}/u/{u['token']}" if u.get("token") and base else ""
    return users


def get_client_ip() -> str:
    # Only trust X-Forwarded-For when explicitly behind a reverse proxy
    if os.environ.get("TRUST_PROXY", "0") == "1":
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return (request.remote_addr or "").strip()


def _wants_json() -> bool:
    if request.args.get("json") == "1":
        return True
    return "application/json" in (request.headers.get("Accept") or "")


# ---------- pages ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("admin"):
            return redirect(url_for("index"))
        return render_template("login.html")
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")
    client_ip = get_client_ip()

    wait = _login_blocked(client_ip, username)
    if wait > 0:
        return jsonify({"ok": False,
                        "error": f"تلاش‌های ناموفق زیاد. {wait} ثانیه دیگر دوباره امتحان کن."}), 429

    admin = db.get_admin(username)
    if admin and db.verify_password(password, admin["password_hash"]):
        db.upgrade_password_hash_if_needed(username, password, admin["password_hash"])
        _login_clear(client_ip, username)
        session.clear()
        session["admin"] = username
        session.permanent = True
        return jsonify({"ok": True})
    _login_record_failure(client_ip, username)
    return jsonify({"ok": False, "error": "نام کاربری یا رمز عبور اشتباه است"}), 401


@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("dashboard.html", admin=session.get("admin"))


# ---------- dashboard API ----------
@app.route("/api/dashboard")
@login_required
def api_dashboard():
    stats = db.dashboard_stats()
    # system info
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        sysinfo = {
            "cpu": round(cpu, 1),
            "ram_used": round(mem.used / 1024 / 1024),
            "ram_total": round(mem.total / 1024 / 1024),
            "ram_pct": round(mem.percent, 1),
            "disk_used_gb": round(disk.used / 1024 / 1024 / 1024, 1),
            "disk_total_gb": round(disk.total / 1024 / 1024 / 1024, 1),
            "disk_pct": round(disk.percent, 1),
            "uptime_sec": int(time.time() - START_TIME),
        }
    except Exception:
        sysinfo = {"cpu": 0, "ram_used": 0, "ram_total": 0, "ram_pct": 0,
                   "disk_used_gb": 0, "disk_total_gb": 0, "disk_pct": 0,
                   "uptime_sec": int(time.time() - START_TIME)}
    # dns process status: check port 53
    import socket
    dns_running = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"\x00\x00", ("127.0.0.1", int(os.environ.get("DNS_PORT", "53"))))
        s.close()
        dns_running = True  # port reachable (best effort)
    except Exception:
        dns_running = True  # can't determine; assume systemd manages it
    stats["system"] = sysinfo
    stats["dns"] = {"running": dns_running, "port": int(os.environ.get("DNS_PORT", "53")),
                    "mode": db.get_setting("dns_mode", "smart")}
    stats["server_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({"ok": True, "data": stats})


# ---------- users API ----------
@app.route("/api/users", methods=["GET"])
@login_required
def api_users_list():
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "all").strip()
    return jsonify({"ok": True, "data": _with_links(db.list_users(search, status))})


@app.route("/api/users", methods=["POST"])
@login_required
def api_users_create():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    ip = (data.get("ip") or "").strip()
    notes = (data.get("notes") or "").strip()
    try:
        days = int(data.get("days", 30))
    except Exception:
        return jsonify({"ok": False, "error": "مدت اعتبار نامعتبر است"}), 400
    if not name:
        return jsonify({"ok": False, "error": "نام کاربر الزامی است"}), 400
    if ip and not valid_ip(ip):
        return jsonify({"ok": False, "error": "آدرس IP نامعتبر است"}), 400
    if days < 1 or days > 3650:
        return jsonify({"ok": False, "error": "مدت اعتبار باید بین ۱ تا ۳۶۵۰ روز باشد"}), 400
    # NOTE: duplicate IPs are allowed (mobile carriers use NAT / shared IPs)
    try:
        user = db.create_user(name, ip, days, notes)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "data": _with_link(user)})


@app.route("/api/users/<int:uid>", methods=["PUT"])
@login_required
def api_users_update(uid):
    data = request.get_json(force=True)
    if "ip" in data and data["ip"] and not valid_ip(data["ip"]):
        return jsonify({"ok": False, "error": "آدرس IP نامعتبر است"}), 400
    try:
        user = db.update_user(uid,
                              name=data.get("name"), ip=data.get("ip"),
                              expiry=data.get("expiry"), notes=data.get("notes"),
                              status=data.get("status"))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    if not user:
        return jsonify({"ok": False, "error": "کاربر یافت نشد"}), 404
    return jsonify({"ok": True, "data": _with_link(user)})


@app.route("/api/users/<int:uid>", methods=["DELETE"])
@login_required
def api_users_delete(uid):
    db.delete_user(uid)
    return jsonify({"ok": True})


@app.route("/api/users/<int:uid>/extend", methods=["POST"])
@login_required
def api_users_extend(uid):
    data = request.get_json(force=True, silent=True) or {}
    try:
        days = int(data.get("days", 30))
    except Exception:
        return jsonify({"ok": False, "error": "عدد نامعتبر"}), 400
    user = db.extend_user(uid, days)
    if not user:
        return jsonify({"ok": False, "error": "کاربر یافت نشد"}), 404
    return jsonify({"ok": True, "data": _with_link(user)})


@app.route("/api/users/<int:uid>/toggle", methods=["POST"])
@login_required
def api_users_toggle(uid):
    user = db.toggle_user(uid)
    if not user:
        return jsonify({"ok": False, "error": "کاربر یافت نشد"}), 404
    return jsonify({"ok": True, "data": _with_link(user)})


@app.route("/api/users/<int:uid>/regen-link", methods=["POST"])
@login_required
def api_users_regen_link(uid):
    user = db.regenerate_token(uid)
    if not user:
        return jsonify({"ok": False, "error": "کاربر یافت نشد"}), 404
    return jsonify({"ok": True, "data": _with_link(user)})


# ---------- public self-service IP update link (NO login) ----------
@app.route("/u/<token>", methods=["GET", "POST"])
def user_link(token):
    user = db.get_user_by_token(token)
    if not user:
        if _wants_json():
            return jsonify({"ok": False, "error": "invalid token"}), 404
        return render_template("link.html", state="invalid"), 404
    detected = get_client_ip()
    expired = user["is_expired"] or user["status"] != "active"
    result, wait = None, 0
    # NOTE: GET never changes anything (safe against link-preview/prefetch bots).
    # Only an explicit POST (button press) updates the IP.
    if request.method == "POST" and not expired:
        if user["ip"] == detected:
            result = "already"
        else:
            try:
                cooldown = int(db.get_setting("link_cooldown_sec", "60"))
            except Exception:
                cooldown = 60
            if cooldown > 0 and user.get("ip_updated_at"):
                try:
                    last = datetime.strptime(user["ip_updated_at"][:19], "%Y-%m-%d %H:%M:%S")
                    wait = cooldown - int((datetime.now() - last).total_seconds())
                except Exception:
                    wait = 0
            if wait > 0:
                result = "cooldown"
            else:
                db.update_user_ip(user["id"], detected)
                user = db.get_user(user["id"]) or user
                result = "ok"
    if _wants_json():
        payload = {"ok": result in ("ok", "already"),
                   "result": result or ("expired" if expired else "none"),
                   "detected_ip": detected, "registered_ip": user["ip"],
                   "days_left": user["days_left"], "wait_sec": max(wait, 0)}
        code = 200 if payload["ok"] else (429 if result == "cooldown" else 403 if expired else 200)
        return jsonify(payload), code
    return render_template("link.html",
                           state="expired" if expired else "form",
                           user=user, detected=detected, result=result, wait=max(wait, 0))


# ---------- logs API ----------
@app.route("/api/logs")
@login_required
def api_logs():
    try:
        user_id = int(request.args.get("user_id") or 0) or None
    except Exception:
        user_id = None
    domain = request.args.get("domain", "").strip()
    action = request.args.get("action", "").strip()
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
        offset = int(request.args.get("offset", 0))
    except Exception:
        limit, offset = 100, 0
    return jsonify({"ok": True, **db.get_logs(user_id, domain, action, limit, offset)})


@app.route("/api/logs", methods=["DELETE"])
@login_required
def api_logs_clear():
    db.clear_logs()
    return jsonify({"ok": True})


# ---------- DNS settings / rules / blocklist ----------
@app.route("/api/settings", methods=["GET"])
@login_required
def api_settings_get():
    return jsonify({"ok": True, "data": db.get_all_settings(),
                    "blocklist_count": db.blocklist_count()})


@app.route("/api/settings", methods=["POST"])
@login_required
def api_settings_set():
    data = request.get_json(force=True)
    allowed = {"upstream1", "upstream2", "upstream_timeout", "cache_enabled",
               "cache_ttl", "cache_max", "log_enabled", "log_retention_days",
               "blocklist_enabled", "refuse_unlisted", "server_ip", "sni_enabled",
               "link_cooldown_sec", "dns_mode", "warp_enabled",
               "server_ipv6", "firewall_extra_ports"}
    clean = {k: str(v).strip() for k, v in data.items() if k in allowed}
    if "upstream1" in clean and not valid_ip(clean["upstream1"]):
        return jsonify({"ok": False, "error": "آپ‌استریم ۱ نامعتبر است"}), 400
    if "upstream2" in clean and clean["upstream2"] and not valid_ip(clean["upstream2"]):
        return jsonify({"ok": False, "error": "آپ‌استریم ۲ نامعتبر است"}), 400
    if "server_ip" in clean and clean["server_ip"] and not valid_ip(clean["server_ip"]):
        return jsonify({"ok": False, "error": "IP سرور نامعتبر است"}), 400
    if "server_ipv6" in clean and clean["server_ipv6"]:
        try:
            import ipaddress as _ip
            if not isinstance(_ip.ip_address(clean["server_ipv6"]), _ip.IPv6Address):
                raise ValueError()
        except Exception:
            return jsonify({"ok": False, "error": "IPv6 سرور نامعتبر است"}), 400
    if "firewall_extra_ports" in clean and clean["firewall_extra_ports"]:
        try:
            fw.parse_extra_ports(clean["firewall_extra_ports"])
        except ValueError:
            return jsonify({"ok": False, "error": "فرمت پورت‌های اضافی فایروال نامعتبر است"}), 400
    if "link_cooldown_sec" in clean:
        try:
            cd = int(clean["link_cooldown_sec"])
            if cd < 0 or cd > 86400:
                raise ValueError()
            clean["link_cooldown_sec"] = str(cd)
        except Exception:
            return jsonify({"ok": False, "error": "مقدار cooldown نامعتبر است"}), 400
    if "dns_mode" in clean and clean["dns_mode"] not in ("smart", "full"):
        return jsonify({"ok": False, "error": "حالت DNS نامعتبر است"}), 400
    if "warp_enabled" in clean and clean["warp_enabled"] not in ("0", "1"):
        return jsonify({"ok": False, "error": "مقدار وارپ نامعتبر است"}), 400
    db.set_settings(clean)
    # DNS server reloads config every 30s automatically
    return jsonify({"ok": True})


@app.route("/api/rules", methods=["GET"])
@login_required
def api_rules_list():
    return jsonify({"ok": True, "data": db.list_rules()})


@app.route("/api/rules", methods=["POST"])
@login_required
def api_rules_add():
    data = request.get_json(force=True)
    domain = (data.get("domain") or "").strip().lower()
    target = (data.get("target_ip") or "").strip()
    if not valid_domain(domain):
        return jsonify({"ok": False, "error": "دامنه نامعتبر است"}), 400
    if not valid_ip(target):
        return jsonify({"ok": False, "error": "IP مقصد نامعتبر است"}), 400
    db.add_rule(domain, target)
    return jsonify({"ok": True})


@app.route("/api/rules/<int:rid>", methods=["DELETE"])
@login_required
def api_rules_del(rid):
    db.delete_rule(rid)
    return jsonify({"ok": True})


@app.route("/api/rules/<int:rid>/toggle", methods=["POST"])
@login_required
def api_rules_toggle(rid):
    db.toggle_rule(rid)
    return jsonify({"ok": True})


@app.route("/api/blocklist", methods=["GET"])
@login_required
def api_block_list():
    return jsonify({"ok": True, "data": db.list_blocklist(), "count": db.blocklist_count()})


@app.route("/api/blocklist", methods=["POST"])
@login_required
def api_block_add():
    data = request.get_json(force=True)
    # single domain or bulk text
    if "domains" in data:
        added, bad = 0, 0
        for line in str(data["domains"]).splitlines():
            d = line.strip().lower()
            if not d or d.startswith("#"):
                continue
            if valid_domain(d):
                db.add_blocked(d)
                added += 1
            else:
                bad += 1
        return jsonify({"ok": True, "added": added, "invalid": bad})
    domain = (data.get("domain") or "").strip().lower()
    if not valid_domain(domain):
        return jsonify({"ok": False, "error": "دامنه نامعتبر است"}), 400
    db.add_blocked(domain)
    return jsonify({"ok": True})


@app.route("/api/blocklist/<int:bid>", methods=["DELETE"])
@login_required
def api_block_del(bid):
    db.delete_blocked(bid)
    return jsonify({"ok": True})


@app.route("/api/blocklist", methods=["DELETE"])
@login_required
def api_block_clear():
    db.clear_blocklist()
    return jsonify({"ok": True})


# ---------- proxy domains (Shekan-like) ----------
@app.route("/api/proxy", methods=["GET"])
@login_required
def api_proxy_list():
    return jsonify({"ok": True, "data": db.list_proxy(), "count": db.proxy_count()})


@app.route("/api/proxy", methods=["POST"])
@login_required
def api_proxy_add():
    data = request.get_json(force=True)
    if "domains" in data:
        added, bad = 0, 0
        for line in str(data["domains"]).splitlines():
            d = line.strip().lower()
            if not d or d.startswith("#"):
                continue
            if valid_domain(d):
                db.add_proxy(d, (data.get("profile") or "general"))
                added += 1
            else:
                bad += 1
        return jsonify({"ok": True, "added": added, "invalid": bad})
    domain = (data.get("domain") or "").strip().lower()
    if not valid_domain(domain):
        return jsonify({"ok": False, "error": "دامنه نامعتبر است"}), 400
    db.add_proxy(domain, (data.get("profile") or "general"))
    return jsonify({"ok": True})


@app.route("/api/proxy/<int:pid>", methods=["DELETE"])
@login_required
def api_proxy_del(pid):
    db.delete_proxy(pid)
    return jsonify({"ok": True})


@app.route("/api/proxy/<int:pid>/toggle", methods=["POST"])
@login_required
def api_proxy_toggle(pid):
    db.toggle_proxy(pid)
    return jsonify({"ok": True})


@app.route("/api/proxy", methods=["DELETE"])
@login_required
def api_proxy_clear():
    db.clear_proxy()
    return jsonify({"ok": True})


@app.route("/api/proxy/seed", methods=["POST"])
@login_required
def api_proxy_seed():
    db.seed_proxy_domains()
    return jsonify({"ok": True, "count": db.proxy_count()})


@app.route("/api/proxy-logs", methods=["GET"])
@login_required
def api_proxy_logs():
    sni = request.args.get("sni", "").strip()
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = int(request.args.get("offset", 0))
    except Exception:
        limit, offset = 50, 0
    return jsonify({"ok": True, **db.get_proxy_logs(limit, offset, sni)})


@app.route("/api/proxy-logs", methods=["DELETE"])
@login_required
def api_proxy_logs_clear():
    db.clear_proxy_logs()
    return jsonify({"ok": True})


# ---------- restore backup ----------
@app.route("/api/restore", methods=["POST"])
@login_required
def api_restore():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "فایلی انتخاب نشده است"}), 400
    if (request.content_length or 0) > 200 * 1024 * 1024:
        return jsonify({"ok": False, "error": "حجم فایل بیش از ۲۰۰ مگابایت است"}), 413
    import sqlite3, shutil, tempfile
    data_dir = os.path.dirname(db.DB_PATH)
    os.makedirs(data_dir, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db", dir=data_dir)
    try:
        f.save(tmp.name)
        tmp.close()
        # validate: must be a DNS-panel database
        try:
            c = sqlite3.connect(tmp.name)
            tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            c.close()
        except Exception:
            return jsonify({"ok": False, "error": "فایل معتبر نیست (دیتابیس SQLite نیست)"}), 400
        need = {"users", "admins", "settings"}
        if not need.issubset(tables):
            return jsonify({"ok": False, "error": "این فایل بکاپ پنل DNS نیست"}), 400
        # checkpoint current WAL, safety-backup current DB (keep last 5)
        try:
            with db.get_db() as conn:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except Exception:
            pass
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safety = os.path.join(data_dir, f"panel.db.before-restore-{stamp}")
        try:
            if os.path.exists(db.DB_PATH):
                shutil.copy2(db.DB_PATH, safety)
            olds = sorted([os.path.join(data_dir, x) for x in os.listdir(data_dir)
                           if x.startswith("panel.db.before-restore-")])
            for old in olds[:-5]:
                os.remove(old)
        except Exception:
            pass
        os.replace(tmp.name, db.DB_PATH)
        for suf in ("-wal", "-shm"):
            try:
                os.remove(db.DB_PATH + suf)
            except OSError:
                pass
        try:
            db.init_db()  # migrate restored (possibly older) schema forward
            n_users = len(db.list_users())
        except Exception as e:
            return jsonify({"ok": False, "error": f"ریستور انجام شد ولی خطا در خواندن: {e}"}), 500
        session.clear()  # force re-login (admin creds come from the backup now)
        return jsonify({"ok": True, "users": n_users, "safety_backup": os.path.basename(safety)})
    finally:
        try:
            os.remove(tmp.name)
        except OSError:
            pass


# ---------- gaming preset ----------
@app.route("/api/preset/gaming", methods=["POST"])
@login_required
def api_preset_gaming():
    db.set_setting("dns_mode", "smart")
    removed = db.remove_deprecated_proxy()
    db.seed_proxy_domains()
    return jsonify({"ok": True, "mode": "smart",
                    "removed_deprecated": removed, "proxy_count": db.proxy_count()})


# ---------- WARP (optional outbound via Cloudflare) ----------
def _detect_warp_ip():
    import subprocess
    for dev in ("warp", "CloudflareWARP"):
        try:
            out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", dev],
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                parts = line.split()
                if "inet" in parts:
                    return parts[parts.index("inet") + 1].split("/")[0]
        except Exception:
            continue
    return ""


@app.route("/api/warp/status", methods=["GET"])
@login_required
def api_warp_status():
    import subprocess, glob
    warp_ip = _detect_warp_ip()
    installed = os.path.exists("/etc/wireguard/warp.conf") or bool(glob.glob("/etc/wireguard/wgcf*"))
    exit_ip = ""
    if warp_ip:
        try:
            r = subprocess.run(["curl", "-s", "--max-time", "8", "--interface", warp_ip,
                                "https://api.ipify.org"],
                               capture_output=True, text=True, timeout=10)
            exit_ip = (r.stdout or "").strip()
        except Exception:
            pass
    return jsonify({"ok": True, "installed": installed, "up": bool(warp_ip),
                    "warp_ip": warp_ip, "exit_ip": exit_ip,
                    "enabled": db.get_setting("warp_enabled", "0") == "1"})


@app.route("/api/warp", methods=["POST"])
@login_required
def api_warp_set():
    data = request.get_json(force=True, silent=True) or {}
    en = str(data.get("enabled", "0")).strip()
    if en not in ("0", "1"):
        return jsonify({"ok": False, "error": "مقدار نامعتبر"}), 400
    if en == "1" and not _detect_warp_ip():
        return jsonify({"ok": False, "error": "وارپ روی سرور فعال نیست! اول install-warp.sh را اجرا کن"}), 400
    db.set_setting("warp_enabled", en)
    return jsonify({"ok": True, "enabled": en == "1"})


# ---------- firewall (UFW) ----------
@app.route("/api/firewall", methods=["GET"])
@login_required
def api_firewall_status():
    st = fw.status()
    st["extras"] = db.get_setting("firewall_extra_ports", "")
    st["ssh_port"] = fw.ssh_port()
    st["panel_port"] = fw.panel_port()
    return jsonify({"ok": True, **st})


@app.route("/api/firewall", methods=["POST"])
@login_required
def api_firewall_set():
    data = request.get_json(force=True, silent=True) or {}
    action = str(data.get("action", "")).strip().lower()
    if action == "enable":
        r = fw.enable_safe(db.get_setting("firewall_extra_ports", ""))
        return jsonify(r), (200 if r["ok"] else 400)
    if action == "disable":
        return jsonify(fw.disable())
    return jsonify({"ok": False, "error": "action نامعتبر"}), 400


@app.route("/api/firewall/allow", methods=["POST"])
@login_required
def api_firewall_allow():
    data = request.get_json(force=True, silent=True) or {}
    r = fw.allow(data.get("port"), data.get("proto", "both"))
    if r["ok"]:
        _sync_extras(add=f"{data.get('port')}/{fw.validate_proto(data.get('proto', 'both'))}")
    return jsonify(r), (200 if r["ok"] else 400)


@app.route("/api/firewall/delete", methods=["POST"])
@login_required
def api_firewall_delete():
    data = request.get_json(force=True, silent=True) or {}
    try:
        p = fw.validate_port(data.get("port"))
        pr = fw.validate_proto(data.get("proto", "both"))
    except ValueError:
        return jsonify({"ok": False, "error": "پورت یا پروتکل نامعتبر است"}), 400
    if (p, pr) in [(53, "udp"), (53, "tcp"), (80, "tcp"), (443, "tcp"),
                   (fw.ssh_port(), "tcp"), (fw.panel_port(), "tcp")]:
        return jsonify({"ok": False, "error": "⛔ حذف پورت حیاتی (SSH/پنل/DNS/پروکسی) ممنوع است"}), 400
    r = fw.delete(p, pr)
    if r["ok"]:
        _sync_extras(remove=f"{p}/{pr}")
    return jsonify(r), (200 if r["ok"] else 400)


def _sync_extras(add="", remove=""):
    """Keep firewall_extra_ports setting in sync with panel-managed rules."""
    try:
        cur = [t.strip() for t in db.get_setting("firewall_extra_ports", "").split(",") if t.strip()]
        if remove and remove in cur:
            cur.remove(remove)
        if add and add not in cur:
            cur.append(add)
        db.set_setting("firewall_extra_ports", ",".join(cur))
    except Exception:
        pass


@app.route("/api/detect-ipv6", methods=["GET"])
@login_required
def api_detect_ipv6():
    import subprocess
    try:
        r = subprocess.run(["curl", "-s", "-6", "--max-time", "10", "https://api6.ipify.org"],
                           capture_output=True, text=True, timeout=12)
        ip = (r.stdout or "").strip()
        import ipaddress as _ip
        if isinstance(_ip.ip_address(ip), _ip.IPv6Address):
            return jsonify({"ok": True, "ipv6": ip})
    except Exception:
        pass
    return jsonify({"ok": False, "error": "سرور IPv6 عمومی ندارد یا در دسترس نیست"}), 400


# ---------- auto-discovery ----------
@app.route("/api/discover", methods=["GET"])
@login_required
def api_discover():
    d = db.discover_candidates()
    d["profiles"] = db.PROXY_PROFILES
    return jsonify({"ok": True, **d})


@app.route("/api/discover/add", methods=["POST"])
@login_required
def api_discover_add():
    data = request.get_json(force=True, silent=True) or {}
    domain = (data.get("domain") or "").strip().lower().rstrip(".")
    if not valid_domain(domain):
        return jsonify({"ok": False, "error": "دامنه نامعتبر است"}), 400
    db.add_proxy(domain, data.get("profile") or "general")
    return jsonify({"ok": True, "count": db.proxy_count()})


@app.route("/api/proxy/seed-profile", methods=["POST"])
@login_required
def api_proxy_seed_profile():
    data = request.get_json(force=True, silent=True) or {}
    profile = (data.get("profile") or "").strip()
    if profile not in db.PROXY_PROFILES:
        return jsonify({"ok": False, "error": "پروفایل نامعتبر است"}), 400
    return jsonify({"ok": True, "count": db.seed_profile(profile)})


# ---------- diagnostics ----------
def _diag_upstreams():
    s = db.get_all_settings()
    return [s.get("upstream1", "8.8.8.8"), s.get("upstream2", "1.1.1.1")]


@app.route("/api/diag", methods=["GET"])
@login_required
def api_diag():
    fresh = request.args.get("fresh", "0") == "1"
    return jsonify(dg.run(_diag_upstreams(), force=fresh))


@app.route("/api/diag/full", methods=["GET"])
@login_required
def api_diag_full():
    """Deep scan: test every domain currently in the proxy list (live pool),
    not just the curated default set. Can take a while with a big list."""
    fresh = request.args.get("fresh", "0") == "1"
    domains = db.get_proxy_set()
    return jsonify(dg.full_scan(domains, force=fresh))


@app.route("/api/service-status", methods=["GET"])
def api_service_status():
    # public (customer link page): summary only, cached
    return jsonify(dg.summary(_diag_upstreams()))


# ---------- admin ----------
@app.route("/api/admin/password", methods=["POST"])
@login_required
def api_change_password():
    data = request.get_json(force=True)
    current = data.get("current") or ""
    new = data.get("new") or ""
    admin = db.get_admin(session.get("admin"))
    if not admin or not db.verify_password(current, admin["password_hash"]):
        return jsonify({"ok": False, "error": "رمز فعلی اشتباه است"}), 400
    if len(new) < 4:
        return jsonify({"ok": False, "error": "رمز جدید باید حداقل ۴ کاراکتر باشد"}), 400
    db.change_admin_password(session.get("admin"), new)
    return jsonify({"ok": True})


@app.route("/api/backup")
@login_required
def api_backup():
    path = db.DB_PATH
    if not os.path.exists(path):
        return jsonify({"ok": False, "error": "فایل دیتابیس یافت نشد"}), 404
    # checkpoint WAL first
    try:
        with db.get_db() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
    except Exception:
        pass
    return send_file(path, as_attachment=True, download_name=f"dns-panel-backup-{datetime.now().strftime('%Y%m%d-%H%M')}.db")


# ---------- background janitor ----------
def _janitor():
    while True:
        time.sleep(3600)
        try:
            db.cleanup_old_logs()
        except Exception:
            pass


threading.Thread(target=_janitor, daemon=True).start()


def create_app():
    db.init_db()
    return app


if __name__ == "__main__":
    db.init_db()
    if not db.has_admin():
        u = os.environ.get("ADMIN_USER", "admin")
        p = os.environ.get("ADMIN_PASS", "admin123")
        db.create_admin(u, p)
        print(f"Default admin created: {u} / {p}  (change it after login!)", flush=True)
    port = int(os.environ.get("PANEL_PORT", db.get_setting("panel_port", "8080")))
    app.run(host="0.0.0.0", port=port)
