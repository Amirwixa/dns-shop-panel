# DNS Shop Panel - Database Layer
import sqlite3
import os
import hashlib
import ipaddress
from datetime import datetime, timedelta
from contextlib import contextmanager
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.environ.get("DNS_PANEL_DB", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "panel.db"))

DEFAULT_SETTINGS = {
    "upstream1": "8.8.8.8",
    "upstream2": "1.1.1.1",
    "upstream_timeout": "2",
    "cache_enabled": "1",
    "cache_ttl": "300",
    "cache_max": "10000",
    "log_enabled": "1",
    "log_retention_days": "7",
    "blocklist_enabled": "1",
    "panel_port": "8080",
    "panel_lang": "fa",
    "refuse_unlisted": "1",  # 1 = REFUSED for unknown IP, 0 = allow (open resolver - NOT recommended)
    "server_ip": "",  # public IP of this server (auto-detected at install) - returned for proxy domains
    "sni_enabled": "1",
    "link_cooldown_sec": "60",  # min seconds between self-service IP updates per user
    "dns_mode": "smart",  # smart = only proxy-list domains (Shekan-like) | full = ALL domains via server
    "warp_enabled": "0",  # 1 = SNI proxy outbound goes through WARP (if installed)
    "server_ipv6": "",  # public IPv6 of server (for AAAA answers of proxied domains); "" = force IPv4
    "firewall_extra_ports": "",  # comma list e.g. "9003,8080/tcp" - re-allowed on firewall enable
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip TEXT NOT NULL,
    expiry DATE NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    notes TEXT DEFAULT '',
    token TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_queries INTEGER DEFAULT 0,
    last_seen TIMESTAMP,
    ip_updated_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS query_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    client_ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    qtype TEXT NOT NULL DEFAULT 'A',
    action TEXT NOT NULL DEFAULT 'allowed',
    response_ms INTEGER DEFAULT 0,
    cached INTEGER DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON query_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_user ON query_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_logs_domain ON query_logs(domain);
CREATE INDEX IF NOT EXISTS idx_logs_ip ON query_logs(client_ip);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    target_ip TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS proxy_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    enabled INTEGER DEFAULT 1,
    profile TEXT NOT NULL DEFAULT 'general',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS proxy_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    client_ip TEXT NOT NULL,
    sni TEXT NOT NULL DEFAULT '',
    target_ip TEXT NOT NULL DEFAULT '',
    port INTEGER DEFAULT 443,
    bytes_up INTEGER DEFAULT 0,
    bytes_down INTEGER DEFAULT 0,
    duration_ms INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'ok',
    dns_ms INTEGER DEFAULT 0,
    connect_ms INTEGER DEFAULT 0,
    err_detail TEXT NOT NULL DEFAULT '',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_plogs_ts ON proxy_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_plogs_ip ON proxy_logs(client_ip);
"""


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def get_db():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def gen_token(nbytes=24) -> str:
    import secrets
    return secrets.token_urlsafe(nbytes)


def _migrate_users(db):
    """Upgrade old users tables: drop UNIQUE(ip) (shared/NAT IPs must be allowed),
    add token + ip_updated_at columns."""
    cols = {r["name"] for r in db.execute("PRAGMA table_info(users)").fetchall()}
    needs_rebuild = False
    try:
        for ix in db.execute("PRAGMA index_list(users)").fetchall():
            if ix["origin"] == "u" and str(ix["name"]).startswith("sqlite_autoindex"):
                info = db.execute(f"PRAGMA index_info({ix['name']})").fetchall()
                if any(c["name"] == "ip" for c in info):
                    needs_rebuild = True
    except Exception:
        pass
    if needs_rebuild:
        db.execute("PRAGMA foreign_keys=OFF")
        db.execute("""CREATE TABLE users_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, ip TEXT NOT NULL, expiry DATE NOT NULL,
            status TEXT NOT NULL DEFAULT 'active', notes TEXT DEFAULT '',
            token TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_queries INTEGER DEFAULT 0, last_seen TIMESTAMP,
            ip_updated_at TIMESTAMP)""")
        common = ["id", "name", "ip", "expiry", "status", "notes",
                  "created_at", "total_queries", "last_seen"]
        if "token" in cols:
            common.append("token")
        if "ip_updated_at" in cols:
            common.append("ip_updated_at")
        clist = ", ".join(common)
        db.execute(f"INSERT INTO users_new ({clist}) SELECT {clist} FROM users")
        db.execute("DROP TABLE users")
        db.execute("ALTER TABLE users_new RENAME TO users")
        db.execute("PRAGMA foreign_keys=ON")
        cols = {r["name"] for r in db.execute("PRAGMA table_info(users)").fetchall()}
    if "token" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN token TEXT")
    if "ip_updated_at" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN ip_updated_at TIMESTAMP")


def _ensure_column(db, table, col, ddl):
    cols = {r["name"] for r in db.execute(f"PRAGMA table_info({table})").fetchall()}
    if col not in cols:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")


def _migrate_proxy(db):
    _ensure_column(db, "proxy_domains", "profile", "TEXT NOT NULL DEFAULT 'general'")
    _ensure_column(db, "proxy_logs", "dns_ms", "INTEGER DEFAULT 0")
    _ensure_column(db, "proxy_logs", "connect_ms", "INTEGER DEFAULT 0")
    _ensure_column(db, "proxy_logs", "err_detail", "TEXT NOT NULL DEFAULT ''")
    # Fix stale/incorrect hostnames seeded by older versions (these never
    # resolved: they were typos of the real provider endpoints).
    RENAMES = {
        "account.epicgames.com": "accounts.epicgames.com",
        "id.sony.com": "id.sonyentertainmentnetwork.com",
    }
    for old, new in RENAMES.items():
        row = db.execute("SELECT id FROM proxy_domains WHERE domain=?", (old,)).fetchone()
        if not row:
            continue
        exists = db.execute("SELECT id FROM proxy_domains WHERE domain=?", (new,)).fetchone()
        if exists:
            db.execute("DELETE FROM proxy_domains WHERE domain=?", (old,))
        else:
            db.execute("UPDATE proxy_domains SET domain=? WHERE domain=?", (new, old))


def init_db():
    with get_db() as db:
        db.executescript(SCHEMA)
        _migrate_users(db)
        _migrate_proxy(db)
        for k, v in DEFAULT_SETTINGS.items():
            db.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, v))
        rows = db.execute("SELECT id FROM users WHERE token IS NULL OR token=''").fetchall()
        for r in rows:
            db.execute("UPDATE users SET token=? WHERE id=?", (gen_token(), r["id"]))
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_token ON users(token)")


def hash_password(password: str) -> str:
    """Secure password hash: PBKDF2-SHA256 with a per-password random salt
    (via werkzeug), 600k iterations. Safe against rainbow tables / GPU cracking."""
    return generate_password_hash(password, method="pbkdf2:sha256:600000")


def _legacy_hash(password: str) -> str:
    """Old (pre-2.1) hashing scheme: unsalted SHA-256. Kept only to verify
    and transparently upgrade existing admin accounts on next login."""
    return hashlib.sha256(("dns-panel::" + password).encode()).hexdigest()


def is_legacy_hash(password_hash: str) -> bool:
    return bool(password_hash) and not password_hash.startswith(("pbkdf2:", "scrypt:"))


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    if is_legacy_hash(password_hash):
        import hmac
        return hmac.compare_digest(_legacy_hash(password), password_hash)
    try:
        return check_password_hash(password_hash, password)
    except Exception:
        return False


# ---------- Admin ----------
def create_admin(username: str, password: str):
    with get_db() as db:
        db.execute(
            "INSERT OR REPLACE INTO admins(username, password_hash) VALUES(?, ?)",
            (username, hash_password(password)),
        )


def get_admin(username: str):
    with get_db() as db:
        return db.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()


def change_admin_password(username: str, new_password: str):
    with get_db() as db:
        db.execute("UPDATE admins SET password_hash=? WHERE username=?", (hash_password(new_password), username))


def upgrade_password_hash_if_needed(username: str, password: str, current_hash: str):
    """Called right after a successful login. If the stored hash is still the
    old unsalted SHA-256 scheme, transparently re-hash with PBKDF2 + salt."""
    if is_legacy_hash(current_hash):
        change_admin_password(username, password)


def has_admin() -> bool:
    with get_db() as db:
        row = db.execute("SELECT COUNT(*) c FROM admins").fetchone()
        return row["c"] > 0


# ---------- Settings ----------
def get_setting(key: str, default=""):
    with get_db() as db:
        row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def get_all_settings() -> dict:
    with get_db() as db:
        rows = db.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}


def set_setting(key: str, value: str):
    with get_db() as db:
        db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (key, str(value)))


def set_settings(data: dict):
    with get_db() as db:
        for k, v in data.items():
            db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (k, str(v)))


# ---------- Users ----------
def _row_to_user(row) -> dict:
    if row is None:
        return None
    d = dict(row)
    d["is_pending"] = not (d.get("ip") or "").strip()
    try:
        exp = datetime.strptime(d["expiry"][:10], "%Y-%m-%d").date()
        today = datetime.now().date()
        d["days_left"] = (exp - today).days
        d["is_expired"] = d["days_left"] < 0
    except Exception:
        d["days_left"] = 0
        d["is_expired"] = True
    if d["is_expired"]:
        d["effective_status"] = "expired"
    elif d["is_pending"] and d["status"] == "active":
        d["effective_status"] = "pending"
    else:
        d["effective_status"] = d["status"]
    return d


def list_users(search="", status="all"):
    with get_db() as db:
        q = "SELECT * FROM users"
        clauses, params = [], []
        if search:
            clauses.append("(name LIKE ? OR ip LIKE ? OR notes LIKE ?)")
            params += [f"%{search}%"] * 3
        if status in ("active", "disabled"):
            clauses.append("status=?")
            params.append(status)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY id DESC"
        rows = db.execute(q, params).fetchall()
        users = [_row_to_user(r) for r in rows]
        if status == "expired":
            users = [u for u in users if u["is_expired"]]
        elif status == "pending":
            users = [u for u in users if u["is_pending"]]
        elif status == "expiring":
            users = [u for u in users if 0 <= u["days_left"] <= 3]
        return users


def get_user(user_id: int):
    with get_db() as db:
        return _row_to_user(db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())


def get_user_by_ip(ip: str):
    with get_db() as db:
        return _row_to_user(db.execute("SELECT * FROM users WHERE ip=? ORDER BY id LIMIT 1", (ip,)).fetchone())


def get_user_by_token(token: str):
    if not token:
        return None
    with get_db() as db:
        return _row_to_user(db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone())


def create_user(name: str, ip: str, days: int, notes=""):
    expiry = (datetime.now() + timedelta(days=int(days))).strftime("%Y-%m-%d")
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO users(name, ip, expiry, status, notes, token) VALUES(?, ?, ?, 'active', ?, ?)",
            (name.strip(), normalize_ip(ip), expiry, notes.strip(), gen_token()),
        )
        uid = cur.lastrowid
    return get_user(uid)


def regenerate_token(user_id: int):
    with get_db() as db:
        for _ in range(5):
            t = gen_token()
            if not db.execute("SELECT id FROM users WHERE token=?", (t,)).fetchone():
                db.execute("UPDATE users SET token=? WHERE id=?", (t, user_id))
                break
    return get_user(user_id)


def update_user_ip(user_id: int, ip: str):
    with get_db() as db:
        db.execute("UPDATE users SET ip=?, ip_updated_at=CURRENT_TIMESTAMP WHERE id=?",
                   (normalize_ip(ip), user_id))
    return get_user(user_id)


def update_user(user_id: int, name=None, ip=None, expiry=None, notes=None, status=None):
    with get_db() as db:
        fields, params = [], []
        if name is not None:
            fields.append("name=?"); params.append(name.strip())
        if ip is not None:
            fields.append("ip=?"); params.append(normalize_ip(ip))
            fields.append("ip_updated_at=CURRENT_TIMESTAMP")
        if expiry is not None:
            fields.append("expiry=?"); params.append(expiry[:10])
        if notes is not None:
            fields.append("notes=?"); params.append(notes)
        if status in ("active", "disabled"):
            fields.append("status=?"); params.append(status)
        if not fields:
            return get_user(user_id)
        params.append(user_id)
        db.execute(f"UPDATE users SET {', '.join(fields)} WHERE id=?", params)
    return get_user(user_id)


def delete_user(user_id: int):
    with get_db() as db:
        db.execute("DELETE FROM users WHERE id=?", (user_id,))


def extend_user(user_id: int, days: int):
    u = get_user(user_id)
    if not u:
        return None
    try:
        exp = datetime.strptime(u["expiry"][:10], "%Y-%m-%d")
    except Exception:
        exp = datetime.now()
    base = max(exp, datetime.now())
    new_expiry = (base + timedelta(days=int(days))).strftime("%Y-%m-%d")
    return update_user(user_id, expiry=new_expiry)


def toggle_user(user_id: int):
    u = get_user(user_id)
    if not u:
        return None
    new_status = "disabled" if u["status"] == "active" else "active"
    return update_user(user_id, status=new_status)


def bump_user_stats(ip: str):
    """Increment query counter + last_seen (called from DNS thread, throttled by caller)."""
    try:
        with get_db() as db:
            db.execute(
                "UPDATE users SET total_queries = total_queries + 1, last_seen = CURRENT_TIMESTAMP WHERE ip=?",
                (ip,),
            )
    except Exception:
        pass


def normalize_ip(ip: str) -> str:
    """Canonical form of an IP (IPv6 compressed+lowercase). Returns stripped input if invalid."""
    ip = (ip or "").strip()
    try:
        return str(ipaddress.ip_address(ip))
    except Exception:
        return ip


def ipv6_prefix64(ip: str):
    """Return /64 network string for an IPv6 address (clients rotate IPs within their /64)."""
    try:
        a = ipaddress.ip_address((ip or "").strip())
        if isinstance(a, ipaddress.IPv6Address):
            return str(ipaddress.ip_network(str(a) + "/64", strict=False))
    except Exception:
        pass
    return None


def find_in_map(ip_map: dict, ip: str):
    """Whitelist lookup: exact match, else IPv6 /64-prefix match (privacy-extension friendly)."""
    if not ip:
        return None
    hit = ip_map.get(normalize_ip(ip))
    if hit is not None:
        return hit
    pfx = ipv6_prefix64(ip)
    if pfx:
        for key, val in ip_map.items():
            if ipv6_prefix64(key) == pfx:
                return val
    return None


def get_user_by_ip_smart(ip: str):
    """get_user_by_ip + normalization + IPv6 /64 fallback (for expired/disabled logging)."""
    if not ip:
        return None
    u = get_user_by_ip(normalize_ip(ip))
    if u is None and normalize_ip(ip) != (ip or "").strip():
        u = get_user_by_ip((ip or "").strip())
    if u is None and ipv6_prefix64(ip):
        pfx = ipv6_prefix64(ip)
        for cand in list_users():
            if (cand.get("ip") or "").strip() and ipv6_prefix64(cand["ip"]) == pfx:
                return cand
    return u


def get_active_ip_map() -> dict:
    """Return {ip: user_dict} for usable accounts (active + not expired). Cached by DNS server."""
    users = list_users()
    out = {}
    for u in users:
        if u["status"] == "active" and not u["is_expired"] and (u["ip"] or "").strip():
            out[normalize_ip(u["ip"])] = u
    return out


# ---------- Logs ----------
def insert_log(user_id, client_ip, domain, qtype, action, response_ms=0, cached=0):
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO query_logs(user_id, client_ip, domain, qtype, action, response_ms, cached) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (user_id, client_ip, domain, qtype, action, response_ms, cached),
            )
    except Exception:
        pass


def get_logs(user_id=None, domain="", action="", limit=100, offset=0):
    with get_db() as db:
        clauses, params = [], []
        if user_id:
            clauses.append("l.user_id=?"); params.append(user_id)
        if domain:
            clauses.append("l.domain LIKE ?"); params.append(f"%{domain}%")
        if action:
            clauses.append("l.action=?"); params.append(action)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        total = db.execute(f"SELECT COUNT(*) c FROM query_logs l{where}", params).fetchone()["c"]
        rows = db.execute(
            f"""SELECT l.*, u.name AS user_name FROM query_logs l
                LEFT JOIN users u ON u.id = l.user_id{where}
                ORDER BY l.id DESC LIMIT ? OFFSET ?""",
            params + [limit, offset],
        ).fetchall()
        return {"total": total, "logs": [dict(r) for r in rows]}


def clear_logs():
    with get_db() as db:
        db.execute("DELETE FROM query_logs")


def cleanup_old_logs():
    try:
        days = int(get_setting("log_retention_days", "7"))
    except Exception:
        days = 7
    with get_db() as db:
        db.execute("DELETE FROM query_logs WHERE timestamp < datetime('now', ?)", (f"-{days} days",))
        db.execute("DELETE FROM proxy_logs WHERE timestamp < datetime('now', ?)", (f"-{days} days",))


# ---------- Stats ----------
def dashboard_stats():
    with get_db() as db:
        total_users = db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        disabled = db.execute("SELECT COUNT(*) c FROM users WHERE status='disabled'").fetchone()["c"]
        expired = db.execute("SELECT COUNT(*) c FROM users WHERE date(expiry) < date('now')").fetchone()["c"]
        expiring = db.execute("SELECT COUNT(*) c FROM users WHERE date(expiry) BETWEEN date('now') AND date('now','+3 days')").fetchone()["c"]
        pending = db.execute("SELECT COUNT(*) c FROM users WHERE ip IS NULL OR ip=''").fetchone()["c"]
        active = total_users - expired - disabled
        if active < 0:
            active = 0
        q_today = db.execute("SELECT COUNT(*) c FROM query_logs WHERE date(timestamp)=date('now')").fetchone()["c"]
        q_total = db.execute("SELECT COUNT(*) c FROM query_logs").fetchone()["c"]
        blocked_today = db.execute("SELECT COUNT(*) c FROM query_logs WHERE date(timestamp)=date('now') AND action IN ('blocked','refused','expired')").fetchone()["c"]
        top_domains = db.execute(
            """SELECT domain, COUNT(*) c FROM query_logs
               WHERE date(timestamp)=date('now') AND action='allowed'
               GROUP BY domain ORDER BY c DESC LIMIT 10"""
        ).fetchall()
        hourly = db.execute(
            """SELECT strftime('%H', timestamp) h, COUNT(*) c FROM query_logs
               WHERE date(timestamp)=date('now') GROUP BY h ORDER BY h"""
        ).fetchall()
        daily = db.execute(
            """SELECT date(timestamp) d, COUNT(*) c FROM query_logs
               WHERE date(timestamp) >= date('now','-6 days') GROUP BY d ORDER BY d"""
        ).fetchall()
        top_users = db.execute(
            """SELECT u.name, u.ip, COUNT(*) c FROM query_logs l
               JOIN users u ON u.id=l.user_id
               WHERE date(l.timestamp)=date('now')
               GROUP BY u.id ORDER BY c DESC LIMIT 10"""
        ).fetchall()
        recent_blocked = db.execute(
            """SELECT l.*, u.name user_name FROM query_logs l LEFT JOIN users u ON u.id=l.user_id
               WHERE l.action IN ('blocked','refused','expired') ORDER BY l.id DESC LIMIT 8"""
        ).fetchall()
        proxy_today = db.execute("SELECT COUNT(*) c FROM proxy_logs WHERE date(timestamp)=date('now') AND status='ok'").fetchone()["c"]
        proxied_dns_today = db.execute("SELECT COUNT(*) c FROM query_logs WHERE date(timestamp)=date('now') AND action='proxied'").fetchone()["c"]
        recent_proxy = db.execute(
            """SELECT p.*, u.name user_name FROM proxy_logs p LEFT JOIN users u ON u.id=p.user_id
               ORDER BY p.id DESC LIMIT 8"""
        ).fetchall()
        return {
            "users": {"total": total_users, "active": active, "expired": expired, "expiring": expiring, "disabled": disabled, "pending": pending},
            "queries": {"today": q_today, "total": q_total, "blocked_today": blocked_today},
            "top_domains": [dict(r) for r in top_domains],
            "hourly": [{"hour": r["h"], "count": r["c"]} for r in hourly],
            "daily": [{"date": r["d"], "count": r["c"]} for r in daily],
            "top_users": [dict(r) for r in top_users],
            "recent_blocked": [dict(r) for r in recent_blocked],
            "proxy": {"today": proxy_today, "dns_today": proxied_dns_today},
            "recent_proxy": [dict(r) for r in recent_proxy],
        }


# ---------- Custom rules / blocklist ----------
def list_rules():
    with get_db() as db:
        return [dict(r) for r in db.execute("SELECT * FROM custom_rules ORDER BY id DESC").fetchall()]


def add_rule(domain, target_ip):
    with get_db() as db:
        db.execute("INSERT OR REPLACE INTO custom_rules(domain, target_ip, enabled) VALUES(?, ?, 1)",
                   (domain.strip().lower().rstrip("."), target_ip.strip()))


def delete_rule(rule_id):
    with get_db() as db:
        db.execute("DELETE FROM custom_rules WHERE id=?", (rule_id,))


def toggle_rule(rule_id):
    with get_db() as db:
        db.execute("UPDATE custom_rules SET enabled = 1 - enabled WHERE id=?", (rule_id,))


def list_blocklist():
    with get_db() as db:
        return [dict(r) for r in db.execute("SELECT * FROM blocklist ORDER BY id DESC LIMIT 5000").fetchall()]


def blocklist_count():
    with get_db() as db:
        return db.execute("SELECT COUNT(*) c FROM blocklist").fetchone()["c"]


def add_blocked(domain):
    with get_db() as db:
        db.execute("INSERT OR IGNORE INTO blocklist(domain, enabled) VALUES(?, 1)",
                   (domain.strip().lower().rstrip("."),))


def delete_blocked(bid):
    with get_db() as db:
        db.execute("DELETE FROM blocklist WHERE id=?", (bid,))


def clear_blocklist():
    with get_db() as db:
        db.execute("DELETE FROM blocklist")


def get_dns_runtime_data():
    """Load rules + blocklist for the DNS server cache."""
    with get_db() as db:
        rules = {r["domain"]: r["target_ip"] for r in db.execute("SELECT domain, target_ip FROM custom_rules WHERE enabled=1").fetchall()}
        blocked = {r["domain"] for r in db.execute("SELECT domain FROM blocklist WHERE enabled=1").fetchall()}
    return rules, blocked


# ---------- Proxy domains (Shekan-like: these resolve to OUR server IP) ----------
# Default list of services known to sanction / geo-block Iranian IPs.
# Admin can freely add/remove via panel. Subdomains match automatically.
PROXY_PROFILES = {
    "general": "🌐 عمومی", "crypto": "💰 کریپتو", "ai": "🤖 هوش مصنوعی",
    "cloud": "☁️ ابری/توسعه‌دهنده", "media": "🎵 رسانه",
    "ea": "🎮 EA", "battlenet": "🎮 بتل‌نت", "epic": "🎮 اپیک",
    "rockstar": "🎮 راک‌استار", "psn": "🎮 پلی‌استیشن",
    "steam": "🎮 استیم", "xbox": "🎮 ایکس‌باکس/مایکروسافت",
    "nintendo": "🎮 نینتندو", "ubisoft": "🎮 یوبی‌سافت",
    "geforce": "🎮 گیم‌استریم (GeForce NOW)",
}

# (domain, profile). Game entries are HTTPS-only endpoints (auth/store/API):
# broad apexes (ea.com, ...) would break gameplay (non-HTTPS ports) and are
# auto-removed (see DEPRECATED_PROXY_DOMAINS).
DEFAULT_PROXY_DOMAINS = [
    ("binance.com", "crypto"), ("okx.com", "crypto"), ("bybit.com", "crypto"),
    ("kucoin.com", "crypto"), ("coinbase.com", "crypto"), ("kraken.com", "crypto"),
    ("bitfinex.com", "crypto"), ("tradingview.com", "crypto"), ("stripe.com", "crypto"),
    ("paypal.com", "crypto"),
    ("openai.com", "ai"), ("chatgpt.com", "ai"), ("anthropic.com", "ai"),
    ("claude.ai", "ai"), ("aistudio.google.com", "ai"), ("ai.google.dev", "ai"),
    ("gemini.google.com", "ai"), ("colab.research.google.com", "ai"),
    ("midjourney.com", "ai"), ("huggingface.co", "ai"), ("kaggle.com", "ai"),
    ("replicate.com", "ai"),
    ("aws.amazon.com", "cloud"), ("cloud.oracle.com", "cloud"), ("oracle.com", "cloud"),
    ("azure.microsoft.com", "cloud"), ("portal.azure.com", "cloud"),
    ("cloud.google.com", "cloud"), ("console.cloud.google.com", "cloud"),
    ("docker.com", "cloud"), ("hub.docker.com", "cloud"), ("cisco.com", "cloud"),
    ("vmware.com", "cloud"), ("broadcom.com", "cloud"), ("nvidia.com", "cloud"),
    ("developer.nvidia.com", "cloud"), ("intel.com", "cloud"), ("adobe.com", "cloud"),
    ("developer.apple.com", "cloud"), ("coursera.org", "cloud"), ("udacity.com", "cloud"),
    ("accounts.ea.com", "ea"), ("signin.ea.com", "ea"), ("api.ea.com", "ea"),
    ("www.ea.com", "ea"), ("help.ea.com", "ea"),
    ("origin.com", "ea"), ("www.origin.com", "ea"), ("api.origin.com", "ea"),
    ("account.battle.net", "battlenet"), ("oauth.battle.net", "battlenet"),
    ("accounts.epicgames.com", "epic"), ("store.epicgames.com", "epic"),
    ("www.epicgames.com", "epic"),
    ("signin.rockstargames.com", "rockstar"), ("socialclub.rockstargames.com", "rockstar"),
    ("store.playstation.com", "psn"), ("www.playstation.com", "psn"),
    ("account.sony.com", "psn"), ("id.sonyentertainmentnetwork.com", "psn"),
    ("auth.api.sonyentertainmentnetwork.com", "psn"),
    ("store.steampowered.com", "steam"), ("steamcommunity.com", "steam"),
    ("api.steampowered.com", "steam"), ("login.steampowered.com", "steam"),
    ("help.steampowered.com", "steam"), ("checkout.steampowered.com", "steam"),
    ("login.live.com", "xbox"), ("account.microsoft.com", "xbox"),
    ("www.xbox.com", "xbox"), ("xbox.com", "xbox"),
    ("login.microsoftonline.com", "xbox"),
    ("authorization.xboxlive.com", "xbox"), ("xsts.auth.xboxlive.com", "xbox"),
    ("accounts.nintendo.com", "nintendo"), ("api.accounts.nintendo.com", "nintendo"),
    ("ec.nintendo.com", "nintendo"), ("www.nintendo.com", "nintendo"),
    ("account.ubisoft.com", "ubisoft"), ("connect.ubisoft.com", "ubisoft"),
    ("public-ubiservices.ubi.com", "ubisoft"),
    ("play.geforcenow.com", "geforce"), ("api.geforcenow.com", "geforce"),
    ("account.nvidia.com", "geforce"),
    ("tiktok.com", "media"), ("spotify.com", "media"),
]

# Broad gaming apexes from older default lists. They break gameplay (non-HTTPS
# ports) and are auto-removed when (re)seeding defaults or applying presets.
DEPRECATED_PROXY_DOMAINS = [
    "ea.com", "battle.net", "blizzard.com", "epicgames.com", "rockstargames.com",
]


def list_proxy():
    with get_db() as db:
        return [dict(r) for r in db.execute("SELECT * FROM proxy_domains ORDER BY id DESC").fetchall()]


def proxy_count():
    with get_db() as db:
        return db.execute("SELECT COUNT(*) c FROM proxy_domains WHERE enabled=1").fetchone()["c"]


def get_proxy_set() -> set:
    with get_db() as db:
        return {r["domain"] for r in db.execute("SELECT domain FROM proxy_domains WHERE enabled=1").fetchall()}


def add_proxy(domain, profile="general"):
    if profile not in PROXY_PROFILES:
        profile = "general"
    with get_db() as db:
        db.execute("INSERT OR IGNORE INTO proxy_domains(domain, enabled, profile) VALUES(?, 1, ?)",
                   (domain.strip().lower().rstrip("."), profile))


def delete_proxy(pid):
    with get_db() as db:
        db.execute("DELETE FROM proxy_domains WHERE id=?", (pid,))


def toggle_proxy(pid):
    with get_db() as db:
        db.execute("UPDATE proxy_domains SET enabled = 1 - enabled WHERE id=?", (pid,))


def clear_proxy():
    with get_db() as db:
        db.execute("DELETE FROM proxy_domains")


def remove_deprecated_proxy():
    """Delete deprecated entries (e.g. gameplay-breaking apexes). Returns count removed."""
    with get_db() as db:
        cur = db.execute(
            f"DELETE FROM proxy_domains WHERE domain IN ({','.join('?' * len(DEPRECATED_PROXY_DOMAINS))})",
            DEPRECATED_PROXY_DOMAINS,
        )
        return cur.rowcount


def seed_proxy_domains():
    with get_db() as db:
        for d, prof in DEFAULT_PROXY_DOMAINS:
            db.execute("INSERT OR IGNORE INTO proxy_domains(domain, enabled, profile) VALUES(?, 1, ?)", (d, prof))
            db.execute("UPDATE proxy_domains SET profile=? WHERE domain=? AND profile='general'", (prof, d))
    remove_deprecated_proxy()


def seed_profile(profile: str) -> int:
    """Add all default domains of one profile. Returns proxy count."""
    with get_db() as db:
        for d, prof in DEFAULT_PROXY_DOMAINS:
            if prof == profile:
                db.execute("INSERT OR IGNORE INTO proxy_domains(domain, enabled, profile) VALUES(?, 1, ?)", (d, prof))
                db.execute("UPDATE proxy_domains SET profile=? WHERE domain=? AND profile='general'", (prof, d))
    remove_deprecated_proxy()
    return proxy_count()


# ---------- Proxy connection logs ----------
def insert_proxy_log(user_id, client_ip, sni, target_ip="", port=443,
                     bytes_up=0, bytes_down=0, duration_ms=0, status="ok",
                     dns_ms=0, connect_ms=0, err_detail=""):
    try:
        with get_db() as db:
            db.execute(
                """INSERT INTO proxy_logs(user_id, client_ip, sni, target_ip, port,
                   bytes_up, bytes_down, duration_ms, status, dns_ms, connect_ms, err_detail)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_id, client_ip, sni, target_ip, port, bytes_up, bytes_down,
                 duration_ms, status, dns_ms, connect_ms, (err_detail or "")[:200]),
            )
    except Exception:
        pass


def _domain_covered(domain: str, patterns) -> bool:
    d = (domain or "").lower().rstrip(".")
    for pat in patterns:
        p = (pat or "").lower().rstrip(".")
        if d == p or d.endswith("." + p):
            return True
    return False


def discover_candidates(limit=20):
    """Auto-discovery: refused SNIs + top queried unlisted domains (for one-click add)."""
    with get_db() as db:
        proxy_set = {r["domain"] for r in db.execute("SELECT domain FROM proxy_domains").fetchall()}
        blocked = {r["domain"] for r in db.execute("SELECT domain FROM blocklist").fetchall()}
        refused = db.execute(
            """SELECT sni, COUNT(*) c, MAX(timestamp) last_seen, COUNT(DISTINCT client_ip) users
               FROM proxy_logs WHERE status='refused_sni' AND sni != ''
               GROUP BY sni ORDER BY c DESC LIMIT ?""", (limit,)).fetchall()
        top = db.execute(
            """SELECT domain, COUNT(*) c, MAX(timestamp) last_seen
               FROM query_logs WHERE domain != '' AND action IN ('allowed','proxied')
               GROUP BY domain ORDER BY c DESC LIMIT 100""").fetchall()
    out_ref, out_top = [], []
    for r in refused:
        if not _domain_covered(r["sni"], proxy_set):
            out_ref.append({"sni": r["sni"], "count": r["c"],
                            "users": r["users"], "last_seen": r["last_seen"]})
    for r in top:
        d = r["domain"]
        if "." not in d or _domain_covered(d, proxy_set) or _domain_covered(d, blocked):
            continue
        if d.endswith(".local") or d.endswith(".lan") or d.endswith(".localdomain") or d.endswith(".arpa"):
            continue
        out_top.append({"domain": d, "count": r["c"], "last_seen": r["last_seen"]})
        if len(out_top) >= limit:
            break
    return {"refused_sni": out_ref[:limit], "top_unlisted": out_top}


def get_proxy_logs(limit=50, offset=0, sni=""):
    with get_db() as db:
        clauses, params = [], []
        if sni:
            clauses.append("p.sni LIKE ?"); params.append(f"%{sni}%")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        total = db.execute(f"SELECT COUNT(*) c FROM proxy_logs p{where}", params).fetchone()["c"]
        rows = db.execute(
            f"""SELECT p.*, u.name AS user_name FROM proxy_logs p
                LEFT JOIN users u ON u.id = p.user_id{where}
                ORDER BY p.id DESC LIMIT ? OFFSET ?""",
            params + [limit, offset],
        ).fetchall()
        return {"total": total, "logs": [dict(r) for r in rows]}


def clear_proxy_logs():
    with get_db() as db:
        db.execute("DELETE FROM proxy_logs")
