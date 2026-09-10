"""Server-side health diagnostics: can THIS server reach EA/PSN/Steam/AI/crypto
services etc? Two modes:
  - run(): a fast, curated set of well-known critical hosts per category
    (what the panel shows by default).
  - full_scan(): tests every domain currently configured in the proxy list
    (admin-triggered "deep scan" — the real, live pool, not a hardcoded one).

Used by the admin panel (full detail) and the customer link page (summary).
Results are cached; ?fresh=1 forces a re-run.
"""
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor

CACHE_TTL = 300
FULL_CACHE_TTL = 600
_cache = {"ts": 0, "data": None}
_full_cache = {"ts": 0, "data": None}

# Curated, representative hosts per category — kept small so the default
# "اجرای تست" button stays fast. Hostnames verified against each provider's
# actual current auth/store endpoints (not guessed): a stale/typo'd hostname
# here would falsely report "قطع" even when the provider is fully reachable.
SERVICES = [
    {"id": "ea", "name": "EA / Origin 🎮", "hosts": ["accounts.ea.com", "www.origin.com"]},
    {"id": "battlenet", "name": "Battle.net 🎮", "hosts": ["account.battle.net"]},
    {"id": "epic", "name": "Epic Games 🎮", "hosts": ["accounts.epicgames.com", "store.epicgames.com"]},
    {"id": "rockstar", "name": "Rockstar 🎮", "hosts": ["signin.rockstargames.com"]},
    {"id": "psn", "name": "PlayStation 🎮", "hosts": ["store.playstation.com", "id.sonyentertainmentnetwork.com"]},
    {"id": "steam", "name": "Steam 🎮", "hosts": ["store.steampowered.com", "steamcommunity.com"]},
    {"id": "xbox", "name": "Xbox / Microsoft 🎮", "hosts": ["login.live.com", "www.xbox.com"]},
    {"id": "nintendo", "name": "Nintendo 🎮", "hosts": ["accounts.nintendo.com"]},
    {"id": "ubisoft", "name": "Ubisoft 🎮", "hosts": ["account.ubisoft.com"]},
    {"id": "geforce", "name": "GeForce NOW 🎮", "hosts": ["play.geforcenow.com"]},
    {"id": "crypto", "name": "کریپتو (Binance/OKX) 💰", "hosts": ["binance.com", "okx.com"]},
    {"id": "ai", "name": "هوش مصنوعی (OpenAI/Claude) 🤖", "hosts": ["chatgpt.com", "claude.ai"]},
    {"id": "cloud", "name": "ابری/توسعه‌دهنده ☁️", "hosts": ["hub.docker.com", "aws.amazon.com"]},
    {"id": "media", "name": "رسانه 🎵", "hosts": ["spotify.com"]},
]

TIMEOUT = 6


def _check_host(host: str) -> dict:
    """Resolve -> TCP 443 connect -> HTTPS GET. Returns timings + status."""
    out = {"host": host, "ok": False, "resolve_ms": None, "connect_ms": None,
           "https_ms": None, "http_code": None, "error": ""}
    t0 = time.time()
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        out["resolve_ms"] = int((time.time() - t0) * 1000)
    except Exception as e:
        out["error"] = f"DNS: {type(e).__name__}"
        return out
    ip = None
    for fam, _, _, _, sa in infos:
        t1 = time.time()
        try:
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((sa[0], 443))
            out["connect_ms"] = int((time.time() - t1) * 1000)
            ip = sa[0]
            break
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            continue
    if ip is None:
        out["error"] = "TCP 443 refused/timeout"
        return out
    out["ip"] = ip
    t2 = time.time()
    try:
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(s, server_hostname=host)
        tls.settimeout(TIMEOUT)
        tls.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = tls.recv(4096).decode("latin1", "replace")
        out["https_ms"] = int((time.time() - t2) * 1000)
        for line in data.splitlines():
            if line.startswith("HTTP/"):
                try:
                    out["http_code"] = int(line.split()[1])
                except Exception:
                    pass
                break
        out["ok"] = out["http_code"] is not None and out["http_code"] < 500
        if not out["ok"] and out["http_code"] is None:
            out["error"] = "no HTTP response"
        elif not out["ok"]:
            out["error"] = f"HTTP {out['http_code']}"
    except Exception as e:
        out["error"] = f"TLS/HTTPS: {type(e).__name__}"
    finally:
        try:
            s.close()
        except Exception:
            pass
    return out


def _check_upstreams(upstreams) -> dict:
    """Send a real DNS query to each upstream, measure latency."""
    out = {}
    try:
        from dnslib import DNSRecord
        q = DNSRecord.question("example.com", "A").pack()
    except Exception:
        return out
    for ups in upstreams:
        if not ups:
            continue
        t0 = time.time()
        try:
            import ipaddress
            fam = socket.AF_INET6 if isinstance(ipaddress.ip_address(ups), ipaddress.IPv6Address) else socket.AF_INET
        except Exception:
            fam = socket.AF_INET
        try:
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.settimeout(4)
            s.sendto(q, (ups, 53))
            s.recvfrom(4096)
            s.close()
            out[ups] = {"ok": True, "ms": int((time.time() - t0) * 1000)}
        except Exception as e:
            out[ups] = {"ok": False, "ms": None, "error": type(e).__name__}
    return out


def run(upstreams=("8.8.8.8", "1.1.1.1"), force=False) -> dict:
    global _cache
    now = time.time()
    if not force and _cache["data"] and now - _cache["ts"] < CACHE_TTL:
        d = dict(_cache["data"])
        d["cached"] = True
        return d
    services = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        for svc in SERVICES:
            results = list(ex.map(_check_host, svc["hosts"]))
            oks = sum(1 for r in results if r["ok"])
            state = "up" if oks == len(results) else ("degraded" if oks else "down")
            services.append({"id": svc["id"], "name": svc["name"],
                             "state": state, "hosts": results})
    ups = _check_upstreams([u for u in upstreams if u])
    data = {"ok": True, "cached": False, "ts": int(now),
            "services": services, "upstreams": ups}
    _cache = {"ts": now, "data": data}
    return dict(data)


def full_scan(domains, force=False) -> dict:
    """Deep scan: test EVERY domain currently configured in the proxy list
    (the real live pool the admin manages), not a hardcoded curated set.
    domains: iterable of hostnames (e.g. from db.get_proxy_set())."""
    global _full_cache
    now = time.time()
    domains = sorted(set(d for d in domains if d))
    if not force and _full_cache["data"] and now - _full_cache["ts"] < FULL_CACHE_TTL \
            and _full_cache["data"].get("domains") == domains:
        d = dict(_full_cache["data"])
        d["cached"] = True
        return d
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(_check_host, domains))
    up = sum(1 for r in results if r["ok"])
    data = {"ok": True, "cached": False, "ts": int(now), "domains": domains,
            "total": len(domains), "up": up, "down": len(domains) - up,
            "results": results}
    _full_cache = {"ts": now, "data": data}
    return dict(data)


def summary(upstreams=("8.8.8.8", "1.1.1.1")) -> dict:
    """Public, non-sensitive summary for the customer link page."""
    d = run(upstreams)
    return {"ok": True, "ts": d["ts"], "cached": d.get("cached", False),
            "services": [{"id": s["id"], "name": s["name"], "state": s["state"]}
                         for s in d["services"]]}
