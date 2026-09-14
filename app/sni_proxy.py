# DNS Shop Panel - SNI/HTTP Transparent Proxy (Shekan-like anti-sanction engine)
#
# How it works (exactly like Shecan / Shelter):
#   1. Our DNS returns THIS server's IP for domains in the proxy list.
#   2. Customer's app/browser connects to server:443 (TLS) or server:80 (HTTP).
#   3. We read the TLS SNI (or HTTP Host header) to find the real destination.
#   4. We connect to the real site from OUR (foreign) IP and relay bytes both ways.
#   5. Destination sees our server IP -> sanctions/geo-blocks don't trigger.
#
# Safety: only whitelisted customer IPs (active, non-expired) and only
# domains in the proxy list are forwarded. Everything else is dropped.
import asyncio
import re
import socket
import threading
import time
import queue

from . import database as db

MAX_HELLO = 64 * 1024
IDLE_TIMEOUT = 120
CONNECT_TIMEOUT = 10
FIRST_BYTES_TIMEOUT = 15
MAX_CONCURRENT = 2000


def domain_match(domain: str, pattern: str) -> bool:
    domain = domain.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    return domain == pattern or domain.endswith("." + pattern)


# ---------- TLS ClientHello / SNI parsing (no external deps) ----------
def parse_sni_from_hello(body: bytes):
    """Parse ClientHello body (without handshake header). Returns SNI hostname or None."""
    try:
        p = 0
        p += 2                      # client version
        p += 32                     # random
        if p >= len(body):
            return None
        sid_len = body[p]; p += 1 + sid_len
        if p + 2 > len(body):
            return None
        cs_len = int.from_bytes(body[p:p + 2], "big"); p += 2 + cs_len
        if p >= len(body):
            return None
        cm_len = body[p]; p += 1 + cm_len
        if p + 2 > len(body):
            return None
        ext_total = int.from_bytes(body[p:p + 2], "big"); p += 2
        ext_end = p + ext_total
        while p + 4 <= len(body) and p < ext_end:
            ext_type = int.from_bytes(body[p:p + 2], "big")
            ext_len = int.from_bytes(body[p + 2:p + 4], "big")
            p += 4
            if p + ext_len > len(body):
                break
            if ext_type == 0x0000:  # server_name
                q = p
                if q + 2 > len(body):
                    break
                list_len = int.from_bytes(body[q:q + 2], "big"); q += 2
                list_end = q + list_len
                while q + 3 <= list_end and q + 3 <= len(body):
                    name_type = body[q]
                    name_len = int.from_bytes(body[q + 1:q + 3], "big")
                    q += 3
                    if q + name_len > len(body):
                        break
                    if name_type == 0:
                        return body[q:q + name_len].decode("ascii", "ignore")
                    q += name_len
                return None
            p += ext_len
    except Exception:
        return None
    return None


async def read_tls_hello(reader: asyncio.StreamReader):
    """Read TLS records until a full ClientHello is buffered.
    Returns (sni, raw_bytes_consumed) or (None, None) on failure."""
    handshake = b""
    raw = b""
    msg_len = None
    try:
        while True:
            hdr = await asyncio.wait_for(reader.readexactly(5), timeout=FIRST_BYTES_TIMEOUT)
            if len(hdr) != 5 or hdr[0] != 0x16 or hdr[1] != 0x03:
                return None, None
            rec_len = int.from_bytes(hdr[3:5], "big")
            if rec_len <= 0 or rec_len > 16384 + 1024:
                return None, None
            payload = await asyncio.wait_for(reader.readexactly(rec_len), timeout=FIRST_BYTES_TIMEOUT)
            if len(payload) != rec_len:
                return None, None
            raw += hdr + payload
            handshake += payload
            if len(raw) > MAX_HELLO:
                return None, None
            if msg_len is None and len(handshake) >= 4:
                if handshake[0] != 0x01:  # not ClientHello
                    return None, None
                msg_len = int.from_bytes(handshake[1:4], "big")
                if msg_len <= 0 or msg_len > MAX_HELLO:
                    return None, None
            if msg_len is not None and len(handshake) >= 4 + msg_len:
                break
        sni = parse_sni_from_hello(handshake[4:4 + msg_len])
        return sni, raw
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        return None, None


async def read_http_host(reader: asyncio.StreamReader, prefix: bytes):
    """Read HTTP request head. Returns (host, raw_bytes) or (None, None)."""
    buf = prefix
    try:
        while b"\r\n\r\n" not in buf:
            if len(buf) > MAX_HELLO:
                return None, None
            chunk = await asyncio.wait_for(reader.read(4096), timeout=FIRST_BYTES_TIMEOUT)
            if not chunk:
                return None, None
            buf += chunk
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin1", "ignore")
        m = re.search(r"(?im)^host:\s*([^\s\r\n]+)", head)
        if not m:
            return None, None
        host = m.group(1).strip()
        host = host.split(":")[0].rstrip(".")  # strip port
        return host, buf
    except (asyncio.TimeoutError, ConnectionError):
        return None, None


def resolve_target(host: str, upstreams):
    """Resolve hostname to IP using panel upstreams (dnslib), fallback to system resolver."""
    try:
        from dnslib import DNSRecord, QTYPE, RCODE
        q = DNSRecord.question(host, "A")
        for ups in upstreams:
            if not ups:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(4)
                s.sendto(q.pack(), (ups, 53))
                data, _ = s.recvfrom(4096)
                s.close()
                r = DNSRecord.parse(data)
                if r.header.rcode == RCODE.NOERROR:
                    ips = [str(x.rdata) for x in r.rr if x.rtype == QTYPE.A]
                    if ips:
                        return ips
            except Exception:
                continue
    except Exception:
        pass
    try:
        return [ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)][:4]
    except Exception:
        return []


class SNIProxy:
    def __init__(self, ports=(80, 443)):
        self.ports = ports
        self.allowed_ips = {}   # ip -> user
        self.proxy_set = set()
        self.refuse_unlisted = True
        self.full_mode = False
        self.upstreams = ["8.8.8.8", "1.1.1.1"]
        self.log_queue = queue.Queue(maxsize=10000)
        self.sem = asyncio.Semaphore(MAX_CONCURRENT)
        self.running = True
        self._user_cache = {}   # ip -> (user_id, ts)

    # ---------- config ----------
    def reload_config(self):
        try:
            s = db.get_all_settings()
            self.refuse_unlisted = s.get("refuse_unlisted", "1") == "1"
            self.full_mode = s.get("dns_mode", "smart") == "full"
            self.upstreams = [s.get("upstream1", "8.8.8.8"), s.get("upstream2", "1.1.1.1")]
            self.allowed_ips = db.get_active_ip_map()
            self.proxy_set = db.get_proxy_set()
        except Exception as e:
            print(f"[SNI] config reload error: {e}", flush=True)

    def _reloader(self):
        while self.running:
            time.sleep(30)
            self.reload_config()

    def _log_worker(self):
        while self.running:
            try:
                item = self.log_queue.get(timeout=2)
            except queue.Empty:
                continue
            try:
                db.insert_proxy_log(**item)
            except Exception as e:
                print(f"[SNI] log error: {e}", flush=True)

    def _log(self, **kw):
        try:
            self.log_queue.put_nowait(kw)
        except queue.Full:
            pass

    def _user_id(self, ip):
        u = self.allowed_ips.get(ip)
        if u:
            return u["id"]
        return None

    def _in_proxy_list(self, host: str) -> bool:
        for pat in self.proxy_set:
            if domain_match(host, pat):
                return True
        return False

    # ---------- connection handling ----------
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, listen_port: int):
        async with self.sem:
            await self._handle(reader, writer, listen_port)

    async def _handle(self, reader, writer, listen_port):
        t0 = time.time()
        try:
            peer = writer.get_extra_info("peername")
            client_ip = peer[0] if peer else "?"
        except Exception:
            client_ip = "?"
        uid = self._user_id(client_ip)

        def close():
            try:
                writer.close()
            except Exception:
                pass

        # 1) IP whitelist
        if self.refuse_unlisted and uid is None:
            self._log(user_id=None, client_ip=client_ip, sni="", port=listen_port,
                      duration_ms=int((time.time() - t0) * 1000), status="refused_ip")
            close()
            return

        # 2) detect TLS vs HTTP
        try:
            first = await asyncio.wait_for(reader.readexactly(5), timeout=FIRST_BYTES_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            close()
            return
        if len(first) != 5:
            close()
            return

        target_host, initial_data, default_port = None, None, listen_port
        if first[0] == 0x16 and first[1] == 0x03:
            # TLS: need full hello; we already consumed 5 bytes -> wrap reader
            rest_reader = _PrependReader(reader, first)
            sni, raw = await read_tls_hello(rest_reader)
            if not sni:
                self._log(user_id=uid, client_ip=client_ip, sni="", port=listen_port,
                          duration_ms=int((time.time() - t0) * 1000), status="error")
                close()
                return
            target_host, initial_data, default_port = sni.strip().rstrip("."), raw, 443
        else:
            host, raw = await read_http_host(reader, first)
            if not host:
                close()
                return
            target_host, initial_data, default_port = host, raw, 80

        # 3) must be in proxy list - unless FULL mode (then any web destination
        #    is allowed; customer IP whitelist above still applies)
        if not self.full_mode and not self._in_proxy_list(target_host):
            self._log(user_id=uid, client_ip=client_ip, sni=target_host, port=listen_port,
                      duration_ms=int((time.time() - t0) * 1000), status="refused_sni")
            close()
            return

        # 4) resolve + connect to real destination
        ips = await asyncio.get_event_loop().run_in_executor(None, resolve_target, target_host, self.upstreams)
        if not ips:
            self._log(user_id=uid, client_ip=client_ip, sni=target_host, port=listen_port,
                      duration_ms=int((time.time() - t0) * 1000), status="error")
            close()
            return
        upstream_reader, upstream_writer, connected_ip = None, None, ""
        for ip in ips:
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, default_port), timeout=CONNECT_TIMEOUT)
                connected_ip = ip
                break
            except (asyncio.TimeoutError, ConnectionError, OSError):
                continue
        if upstream_reader is None:
            self._log(user_id=uid, client_ip=client_ip, sni=target_host, port=listen_port,
                      duration_ms=int((time.time() - t0) * 1000), status="error")
            close()
            return

        # 5) relay both directions
        stats = [0, 0]
        try:
            upstream_writer.write(initial_data)
            await upstream_writer.drain()
            stats[0] += len(initial_data)
            t1 = asyncio.create_task(self._pipe(reader, upstream_writer, stats, 0))
            t2 = asyncio.create_task(self._pipe(upstream_reader, writer, stats, 1))
            done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            for w in (writer, upstream_writer):
                try:
                    w.close()
                except Exception:
                    pass
        self._log(user_id=uid, client_ip=client_ip, sni=target_host, target_ip=connected_ip,
                  port=default_port, bytes_up=stats[0], bytes_down=stats[1],
                  duration_ms=int((time.time() - t0) * 1000), status="ok")

    @staticmethod
    async def _pipe(reader, writer, stats, idx):
        try:
            while True:
                data = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                stats[idx] += len(data)
        except (asyncio.TimeoutError, ConnectionError, asyncio.CancelledError):
            pass
        try:
            writer.close()
        except Exception:
            pass

    # ---------- lifecycle ----------
    async def serve(self):
        self.reload_config()
        threading.Thread(target=self._reloader, daemon=True).start()
        threading.Thread(target=self._log_worker, daemon=True).start()
        servers = []
        for port in self.ports:
            srv = await asyncio.start_server(
                lambda r, w, p=port: self.handle(r, w, p), "0.0.0.0", port)
            servers.append(srv)
            print(f"[SNI] listening on 0.0.0.0:{port}", flush=True)
        async with servers[0]:
            await asyncio.gather(*(s.serve_forever() for s in servers))


class _PrependReader:
    """Wraps StreamReader to 'unread' already-consumed bytes."""
    def __init__(self, reader, prefix: bytes):
        self._r = reader
        self._buf = bytearray(prefix)

    async def readexactly(self, n):
        while len(self._buf) < n:
            chunk = await self._r.read(n - len(self._buf))
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(self._buf), n)
            self._buf += chunk
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


def run_standalone():
    import os
    ports = [int(p) for p in os.environ.get("SNI_PORTS", "80,443").split(",") if p.strip()]
    proxy = SNIProxy(tuple(ports))
    print(f"[SNI] Anti-sanction proxy starting on ports {ports} (Ctrl+C to stop)", flush=True)
    try:
        asyncio.run(proxy.serve())
    except KeyboardInterrupt:
        proxy.running = False


if __name__ == "__main__":
    run_standalone()
