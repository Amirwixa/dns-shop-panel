# DNS Shop Panel - Web Panel (Flask)
import os
import re
import time
import threading
import ipaddress
from functools import wraps
from datetime import datetime
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, send_file

from . import database as db

APP_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(APP_DIR)

app = Flask(__name__, template_folder=os.path.join(APP_DIR, "templates"),
            static_folder=os.path.join(APP_DIR, "static"))
app.secret_key = os.environ.get("PANEL_SECRET", "change-me-please-" + str(time.time()))
app.config["JSON_AS_ASCII"] = False

START_TIME = time.time()


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
    admin = db.get_admin(username)
    if admin and db.verify_password(password, admin["password_hash"]):
        session["admin"] = username
        session.permanent = True
        return jsonify({"ok": True})
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
    if not valid_ip(ip):
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
               "link_cooldown_sec", "dns_mode"}
    clean = {k: str(v).strip() for k, v in data.items() if k in allowed}
    if "upstream1" in clean and not valid_ip(clean["upstream1"]):
        return jsonify({"ok": False, "error": "آپ‌استریم ۱ نامعتبر است"}), 400
    if "upstream2" in clean and clean["upstream2"] and not valid_ip(clean["upstream2"]):
        return jsonify({"ok": False, "error": "آپ‌استریم ۲ نامعتبر است"}), 400
    if "server_ip" in clean and clean["server_ip"] and not valid_ip(clean["server_ip"]):
        return jsonify({"ok": False, "error": "IP سرور نامعتبر است"}), 400
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
                db.add_proxy(d)
                added += 1
            else:
                bad += 1
        return jsonify({"ok": True, "added": added, "invalid": bad})
    domain = (data.get("domain") or "").strip().lower()
    if not valid_domain(domain):
        return jsonify({"ok": False, "error": "دامنه نامعتبر است"}), 400
    db.add_proxy(domain)
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
