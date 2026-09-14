# DNS Shop Panel - Database Layer
import sqlite3
import os
import hashlib
from datetime import datetime, timedelta
from contextlib import contextmanager

DB_PATH = os.environ.get("DNS_PANEL_DB", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "panel.db"))

DEFAULT_SETTINGS = {
    "upstream1": "8.8.8.8",
    "upstream2": "1.1.1.1",
    "upstream_timeout": "5",
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


def init_db():
    with get_db() as db:
        db.executescript(SCHEMA)
        _migrate_users(db)
        for k, v in DEFAULT_SETTINGS.items():
            db.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, v))
        rows = db.execute("SELECT id FROM users WHERE token IS NULL OR token=''").fetchall()
        for r in rows:
            db.execute("UPDATE users SET token=? WHERE id=?", (gen_token(), r["id"]))
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_token ON users(token)")


def hash_password(password: str) -> str:
    return hashlib.sha256(("dns-panel::" + password).encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


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
    try:
        exp = datetime.strptime(d["expiry"][:10], "%Y-%m-%d").date()
        today = datetime.now().date()
        d["days_left"] = (exp - today).days
        d["is_expired"] = d["days_left"] < 0
    except Exception:
        d["days_left"] = 0
        d["is_expired"] = True
    d["effective_status"] = "expired" if d["is_expired"] else d["status"]
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
            (name.strip(), ip.strip(), expiry, notes.strip(), gen_token()),
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
                   (ip.strip(), user_id))
    return get_user(user_id)


def update_user(user_id: int, name=None, ip=None, expiry=None, notes=None, status=None):
    with get_db() as db:
        fields, params = [], []
        if name is not None:
            fields.append("name=?"); params.append(name.strip())
        if ip is not None:
            fields.append("ip=?"); params.append(ip.strip())
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


def get_active_ip_map() -> dict:
    """Return {ip: user_dict} for usable accounts (active + not expired). Cached by DNS server."""
    users = list_users()
    out = {}
    for u in users:
        if u["status"] == "active" and not u["is_expired"]:
            out[u["ip"]] = u
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
            "users": {"total": total_users, "active": active, "expired": expired, "expiring": expiring, "disabled": disabled},
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
DEFAULT_PROXY_DOMAINS = [
    # Crypto / finance (block Iranian IPs)
    "binance.com", "okx.com", "bybit.com", "kucoin.com", "coinbase.com",
    "kraken.com", "bitfinex.com", "tradingview.com", "stripe.com", "paypal.com",
    # AI (block Iran region)
    "openai.com", "chatgpt.com", "anthropic.com", "claude.ai",
    "aistudio.google.com", "ai.google.dev", "gemini.google.com", "colab.research.google.com",
    "midjourney.com", "huggingface.co", "kaggle.com", "replicate.com",
    # Cloud / dev tools
    "aws.amazon.com", "cloud.oracle.com", "oracle.com",
    "azure.microsoft.com", "portal.azure.com", "cloud.google.com", "console.cloud.google.com",
    "docker.com", "hub.docker.com", "cisco.com", "vmware.com", "broadcom.com",
    "nvidia.com", "developer.nvidia.com", "intel.com", "adobe.com",
    "developer.apple.com", "coursera.org", "udacity.com",
    # Game / entertainment launchers (sanctioned for Iran)
    "battle.net", "blizzard.com", "ea.com", "epicgames.com", "rockstargames.com",
    "tiktok.com", "spotify.com",
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


def add_proxy(domain):
    with get_db() as db:
        db.execute("INSERT OR IGNORE INTO proxy_domains(domain, enabled) VALUES(?, 1)",
                   (domain.strip().lower().rstrip("."),))


def delete_proxy(pid):
    with get_db() as db:
        db.execute("DELETE FROM proxy_domains WHERE id=?", (pid,))


def toggle_proxy(pid):
    with get_db() as db:
        db.execute("UPDATE proxy_domains SET enabled = 1 - enabled WHERE id=?", (pid,))


def clear_proxy():
    with get_db() as db:
        db.execute("DELETE FROM proxy_domains")


def seed_proxy_domains():
    with get_db() as db:
        for d in DEFAULT_PROXY_DOMAINS:
            db.execute("INSERT OR IGNORE INTO proxy_domains(domain, enabled) VALUES(?, 1)", (d,))


# ---------- Proxy connection logs ----------
def insert_proxy_log(user_id, client_ip, sni, target_ip="", port=443,
                     bytes_up=0, bytes_down=0, duration_ms=0, status="ok"):
    try:
        with get_db() as db:
            db.execute(
                """INSERT INTO proxy_logs(user_id, client_ip, sni, target_ip, port,
                   bytes_up, bytes_down, duration_ms, status)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_id, client_ip, sni, target_ip, port, bytes_up, bytes_down, duration_ms, status),
            )
    except Exception:
        pass


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
