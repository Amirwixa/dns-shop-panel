# DNS Shop Panel - Lightweight SmartDNS Server (UDP + TCP, port 53)
# Features: IP whitelist (per-user accounts + expiry), upstream forwarding,
# in-memory cache, blocklist, custom rules, per-query logging.
import socket
import threading
import time
import queue
from datetime import datetime

try:
    from dnslib import DNSRecord, DNSHeader, RR, QTYPE, RCODE, A
except ImportError:
    raise SystemExit("dnslib is not installed. Run: pip install -r requirements.txt")

from . import database as db

QTYPE_REV = {v: k for k, v in QTYPE.__dict__.items() if isinstance(v, int)}


def qtype_name(q):
    try:
        return QTYPE.get(q, str(q))
    except Exception:
        return str(q)


def domain_match(domain: str, pattern: str) -> bool:
    """Exact or subdomain match: sub.example.com matches example.com."""
    domain = domain.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    return domain == pattern or domain.endswith("." + pattern)


# Special-use / LAN names that must NEVER be proxied (even in full mode),
# otherwise the customer's local network would break.
LOCAL_SUFFIXES = ("localhost", "local", "lan", "home", "internal", "intranet",
                  "localdomain", "invalid", "arpa")


def is_local_name(domain: str) -> bool:
    d = (domain or "").lower().rstrip(".")
    if not d or "." not in d:  # single-label names (router, printer, ...) = LAN
        return True
    return any(d == s or d.endswith("." + s) for s in LOCAL_SUFFIXES)


class DNSStats:
    def __init__(self):
        self.start_time = time.time()
        self.queries = 0
        self.allowed = 0
        self.refused = 0
        self.blocked = 0
        self.cache_hits = 0
        self.lock = threading.Lock()

    def bump(self, field):
        with self.lock:
            setattr(self, field, getattr(self, field) + 1)

    def snapshot(self, cache_size):
        with self.lock:
            return {
                "uptime_sec": int(time.time() - self.start_time),
                "queries": self.queries,
                "allowed": self.allowed,
                "refused": self.refused,
                "blocked": self.blocked,
                "cache_hits": self.cache_hits,
                "cache_size": cache_size,
                "running": True,
            }


class SmartDNSServer:
    def __init__(self, host="0.0.0.0", port=53):
        self.host = host
        self.port = port
        self.running = False
        self.cache = {}  # (domain, qtype) -> (raw_response, expire_at)
        self.cache_lock = threading.Lock()
        self.allowed_ips = {}   # ip -> user dict
        self.rules = {}         # domain -> ip
        self.blocked = set()    # domains
        self.proxy_set = set()  # Shekan-like domains -> resolve to our server IP
        self.server_ip = ""
        self.settings = {}
        self.stats = DNSStats()
        self.log_queue = queue.Queue(maxsize=10000)
        self._last_bump = {}    # ip -> last bump timestamp (throttle DB writes)

    # ---------- config reload ----------
    def reload_config(self):
        try:
            self.settings = db.get_all_settings()
            self.allowed_ips = db.get_active_ip_map()
            self.rules, self.blocked = db.get_dns_runtime_data()
            new_proxy = db.get_proxy_set()
            old_proxy = self.proxy_set
            self.proxy_set = new_proxy
            self.server_ip = (self.settings.get("server_ip") or "").strip()
            new_mode = self.settings.get("dns_mode", "smart")
            if new_mode != getattr(self, "_last_mode", new_mode):
                self._last_mode = new_mode
                with self.cache_lock:
                    self.cache.clear()
            # purge cached entries for domains whose proxy state changed
            if new_proxy != old_proxy:
                changed = new_proxy | old_proxy
                with self.cache_lock:
                    dead = [k for k in self.cache
                            if any(domain_match(k[0], pat) for pat in changed)]
                    for k in dead:
                        self.cache.pop(k, None)
        except Exception as e:
            print(f"[DNS] config reload error: {e}", flush=True)

    def _reloader_loop(self):
        while self.running:
            time.sleep(30)
            self.reload_config()
            # prune expired cache
            now = time.time()
            with self.cache_lock:
                dead = [k for k, (_, exp) in self.cache.items() if exp < now]
                for k in dead:
                    self.cache.pop(k, None)

    # ---------- logging worker ----------
    def _log_worker(self):
        batch_user = {}
        while self.running:
            try:
                item = self.log_queue.get(timeout=2)
            except queue.Empty:
                continue
            try:
                if self.settings.get("log_enabled", "1") == "1":
                    db.insert_log(**item)
                # throttle total_queries increments: max once per 60s per IP
                ip = item.get("client_ip")
                now = time.time()
                if ip and (now - self._last_bump.get(ip, 0) > 60):
                    self._last_bump[ip] = now
                    db.bump_user_stats(ip)
            except Exception as e:
                print(f"[DNS] log error: {e}", flush=True)

    def _log(self, user_id, client_ip, domain, qtype, action, ms=0, cached=0):
        try:
            self.log_queue.put_nowait({
                "user_id": user_id, "client_ip": client_ip, "domain": domain,
                "qtype": qtype, "action": action, "response_ms": ms, "cached": cached,
            })
        except queue.Full:
            pass

    # ---------- query handling ----------
    def _is_blocked(self, domain):
        if self.settings.get("blocklist_enabled", "1") != "1":
            return False
        for pat in self.blocked:
            if domain_match(domain, pat):
                return True
        return False

    def _custom_ip(self, domain):
        for pat, ip in self.rules.items():
            if domain_match(domain, pat):
                return ip
        return None

    def _is_proxied(self, domain):
        """Shekan-like: is this a sanctioned domain that must resolve to our server?"""
        if self.settings.get("sni_enabled", "1") != "1":
            return False
        if not self.server_ip:
            return False
        if self.settings.get("dns_mode", "smart") == "full":
            # FULL-TUNNEL: everything via our server (except LAN/special names)
            return not is_local_name(domain)
        for pat in self.proxy_set:
            if domain_match(domain, pat):
                return True
        return False

    def _forward(self, data):
        upstreams = [self.settings.get("upstream1", "8.8.8.8"), self.settings.get("upstream2", "1.1.1.1")]
        try:
            timeout = int(self.settings.get("upstream_timeout", "5"))
        except Exception:
            timeout = 5
        last_err = None
        for ups in upstreams:
            if not ups:
                continue
            try:
                t0 = time.time()
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                s.sendto(data, (ups, 53))
                resp, _ = s.recvfrom(4096)
                s.close()
                return resp, int((time.time() - t0) * 1000)
            except Exception as e:
                last_err = e
                continue
        raise last_err or Exception("all upstreams failed")

    def handle_query(self, data: bytes, client_ip: str):
        """Returns raw DNS response bytes."""
        self.stats.bump("queries")
        try:
            req = DNSRecord.parse(data)
        except Exception:
            return None
        if not req.questions:
            return None
        q = req.questions[0]
        domain = str(q.qname).rstrip(".").lower()
        qt = qtype_name(q.qtype)

        user = self.allowed_ips.get(client_ip)
        if user is None:
            # check if IP belongs to expired/disabled user for better logging
            try:
                full = db.get_user_by_ip(client_ip)
            except Exception:
                full = None
            if full and (full["is_expired"] or full["status"] != "active"):
                self.stats.bump("refused")
                self._log(full["id"], client_ip, domain, qt, "expired")
                reply = req.reply()
                reply.header.rcode = RCODE.REFUSED
                return reply.pack()
            if self.settings.get("refuse_unlisted", "1") == "1":
                self.stats.bump("refused")
                self._log(None, client_ip, domain, qt, "refused")
                reply = req.reply()
                reply.header.rcode = RCODE.REFUSED
                return reply.pack()
            uid = None  # open-resolver mode (NOT recommended for paid service)
        else:
            uid = user["id"]

        # 1) blocklist
        if q.qtype == QTYPE.A and self._is_blocked(domain):
            self.stats.bump("blocked")
            self._log(uid, client_ip, domain, qt, "blocked")
            reply = req.reply()
            reply.add_answer(RR(q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
            return reply.pack()

        # 2) custom rules
        custom_ip = self._custom_ip(domain) if q.qtype == QTYPE.A else None
        if custom_ip:
            self.stats.bump("allowed")
            self._log(uid, client_ip, domain, qt, "custom")
            reply = req.reply()
            try:
                reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(custom_ip), ttl=300))
            except Exception:
                reply.header.rcode = RCODE.SERVFAIL
            return reply.pack()

        # 2.5) proxy domains (Shekan-like): return OUR server IP so traffic
        #     goes through our SNI proxy and sanctions don't trigger.
        if self._is_proxied(domain):
            if q.qtype == QTYPE.AAAA:
                # force IPv4 so traffic goes through our SNI proxy
                self.stats.bump("allowed")
                self._log(uid, client_ip, domain, qt, "proxied")
                return req.reply().pack()  # NOERROR + no answers (NODATA)
            if q.qtype == QTYPE.A:
                self.stats.bump("allowed")
                self._log(uid, client_ip, domain, qt, "proxied")
                reply = req.reply()
                try:
                    reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(self.server_ip), ttl=60))
                except Exception:
                    reply.header.rcode = RCODE.SERVFAIL
                return reply.pack()
            # other qtypes fall through to upstream

        # 3) cache
        cache_enabled = self.settings.get("cache_enabled", "1") == "1"
        ckey = (domain, qt)
        if cache_enabled:
            with self.cache_lock:
                hit = self.cache.get(ckey)
                if hit and hit[1] > time.time():
                    try:
                        cached = DNSRecord.parse(hit[0])
                        cached.header.id = req.header.id  # fix transaction id
                        self.stats.bump("allowed")
                        self.stats.bump("cache_hits")
                        self._log(uid, client_ip, domain, qt, "allowed", 0, 1)
                        return cached.pack()
                    except Exception:
                        pass

        # 4) forward upstream
        try:
            resp_data, ms = self._forward(data)
            self.stats.bump("allowed")
            self._log(uid, client_ip, domain, qt, "allowed", ms, 0)
            if cache_enabled:
                try:
                    ttl = int(self.settings.get("cache_ttl", "300"))
                    max_n = int(self.settings.get("cache_max", "10000"))
                except Exception:
                    ttl, max_n = 300, 10000
                # only cache successful NOERROR responses
                try:
                    parsed = DNSRecord.parse(resp_data)
                    if parsed.header.rcode == RCODE.NOERROR and parsed.rr:
                        with self.cache_lock:
                            if len(self.cache) >= max_n:
                                # evict oldest 10%
                                keys = list(self.cache.keys())[: max_n // 10 or 1]
                                for k in keys:
                                    self.cache.pop(k, None)
                            self.cache[ckey] = (resp_data, time.time() + ttl)
                except Exception:
                    pass
            return resp_data
        except Exception as e:
            print(f"[DNS] upstream error for {domain}: {e}", flush=True)
            reply = req.reply()
            reply.header.rcode = RCODE.SERVFAIL
            self._log(uid, client_ip, domain, qt, "allowed", 0, 0)
            return reply.pack()

    # ---------- sockets ----------
    def _udp_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(2)
        print(f"[DNS] UDP listening on {self.host}:{self.port}", flush=True)
        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[DNS] udp recv error: {e}", flush=True)
                continue
            threading.Thread(target=self._serve_udp, args=(sock, data, addr), daemon=True).start()
        sock.close()

    def _serve_udp(self, sock, data, addr):
        try:
            resp = self.handle_query(data, addr[0])
            if resp:
                sock.sendto(resp, addr)
        except Exception as e:
            print(f"[DNS] udp serve error: {e}", flush=True)

    def _tcp_loop(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(50)
        srv.settimeout(2)
        print(f"[DNS] TCP listening on {self.host}:{self.port}", flush=True)
        while self.running:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[DNS] tcp accept error: {e}", flush=True)
                continue
            threading.Thread(target=self._serve_tcp, args=(conn, addr), daemon=True).start()
        srv.close()

    def _serve_tcp(self, conn, addr):
        try:
            conn.settimeout(10)
            while self.running:
                hdr = self._recvn(conn, 2)
                if not hdr:
                    break
                ln = int.from_bytes(hdr, "big")
                if ln <= 0 or ln > 4096:
                    break
                data = self._recvn(conn, ln)
                if not data:
                    break
                resp = self.handle_query(data, addr[0])
                if resp:
                    conn.sendall(len(resp).to_bytes(2, "big") + resp)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _recvn(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # ---------- lifecycle ----------
    def start(self):
        self.running = True
        self.reload_config()
        threading.Thread(target=self._reloader_loop, daemon=True).start()
        threading.Thread(target=self._log_worker, daemon=True).start()
        threading.Thread(target=self._udp_loop, daemon=True).start()
        threading.Thread(target=self._tcp_loop, daemon=True).start()

    def stop(self):
        self.running = False

    def snapshot(self):
        with self.cache_lock:
            size = len(self.cache)
        return self.stats.snapshot(size)


def run_standalone(host="0.0.0.0", port=53):
    import os
    port = int(os.environ.get("DNS_PORT", port))
    host = os.environ.get("DNS_HOST", host)
    server = SmartDNSServer(host, port)
    server.start()
    print(f"[DNS] SmartDNS running on {host}:{port} (Ctrl+C to stop)", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    run_standalone()
