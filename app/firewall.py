"""UFW firewall management for DNS Shop Panel.

The panel runs as root, so ufw is called directly. All inputs are strictly
validated here (port range, protocol allowlist) - never pass raw user input
to the shell (subprocess is used with arg lists, no shell=True).
"""
import os
import re
import shutil
import subprocess

UFW = shutil.which("ufw") or "/usr/sbin/ufw"
PROTOS = ("tcp", "udp", "both")
_RULE_RE = re.compile(r"^(\S+)\s+(ALLOW|DENY|REJECT|LIMIT)\b", re.IGNORECASE)


def installed() -> bool:
    return os.path.exists(UFW) and os.access(UFW, os.X_OK)


def _run(*args, timeout=20):
    return subprocess.run([UFW, *args], capture_output=True, text=True, timeout=timeout)


def validate_port(port) -> int:
    p = int(str(port).strip())
    if p < 1 or p > 65535:
        raise ValueError("port")
    return p


def validate_proto(proto: str) -> str:
    pr = (proto or "both").strip().lower()
    if pr not in PROTOS:
        raise ValueError("proto")
    return pr


def status() -> dict:
    """Return {installed, active, rules:[{target, action, v6}], raw}."""
    if not installed():
        return {"installed": False, "active": False, "rules": [], "raw": ""}
    try:
        r = _run("status")
        out = (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return {"installed": True, "active": False, "rules": [], "raw": f"error: {e}"}
    active = out.lower().startswith("status: active")
    rules = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line or line.startswith("--") or line.startswith("To "):
            continue
        m = _RULE_RE.match(line)
        if not m:
            continue
        target, action = m.group(1), m.group(2).upper()
        rules.append({"target": target, "action": action, "v6": "(v6)" in line})
    return {"installed": True, "active": active, "rules": rules, "raw": out.strip()[:2000]}


def allow(port, proto="both") -> dict:
    """Allow a port. Returns {ok, ...}."""
    if not installed():
        return {"ok": False, "error": "UFW نصب نیست"}
    try:
        p = validate_port(port)
        pr = validate_proto(proto)
    except ValueError:
        return {"ok": False, "error": "پورت یا پروتکل نامعتبر است"}
    protos = ("tcp", "udp") if pr == "both" else (pr,)
    outs = []
    for t in protos:
        try:
            r = _run("allow", f"{p}/{t}")
            outs.append(((r.stdout or "") + (r.stderr or "")).strip())
        except Exception as e:
            return {"ok": False, "error": str(e)}
    return {"ok": True, "detail": " | ".join(o for o in outs if o)[:300]}


def delete(port, proto="both") -> dict:
    if not installed():
        return {"ok": False, "error": "UFW نصب نیست"}
    try:
        p = validate_port(port)
        pr = validate_proto(proto)
    except ValueError:
        return {"ok": False, "error": "پورت یا پروتکل نامعتبر است"}
    protos = ("tcp", "udp") if pr == "both" else (pr,)
    for t in protos:
        try:
            # delete by rule spec is non-interactive; pipe "y" just in case
            subprocess.run([UFW, "delete", "allow", f"{p}/{t}"],
                           input="y\n", capture_output=True, text=True, timeout=20)
        except Exception as e:
            return {"ok": False, "error": str(e)}
    return {"ok": True}


def ssh_port() -> int:
    """Detect SSH port from sshd_config (default 22)."""
    try:
        with open("/etc/ssh/sshd_config", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split()
                if len(parts) >= 2 and parts[0].lower() == "port":
                    try:
                        p = int(parts[1])
                        if 1 <= p <= 65535:
                            return p
                    except ValueError:
                        continue
    except OSError:
        pass
    return 22


def panel_port() -> int:
    try:
        return int(os.environ.get("PANEL_PORT", "8080"))
    except ValueError:
        return 8080


def parse_extra_ports(spec: str):
    """Parse '9003,8080/tcp,7777/udp' -> [(port, proto), ...]. Raises ValueError."""
    out = []
    for tok in (spec or "").replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "/" in tok:
            port, proto = tok.split("/", 1)
            proto = proto.strip().lower()
        else:
            port, proto = tok, "both"
        out.append((validate_port(port), validate_proto(proto)))
    return out


def enable_safe(extra_spec="") -> dict:
    """Allow vital ports first, then enable. Never enable a bare firewall."""
    if not installed():
        return {"ok": False, "error": "UFW نصب نیست"}
    vital = [(ssh_port(), "tcp"), (panel_port(), "tcp"),
             (53, "udp"), (53, "tcp"), (80, "tcp"), (443, "tcp")]
    try:
        extras = parse_extra_ports(extra_spec)
    except ValueError:
        return {"ok": False, "error": "فرمت پورت‌های اضافی نامعتبر است"}
    for p, pr in vital + extras:
        r = allow(p, pr)
        if not r["ok"]:
            return {"ok": False, "error": f"خطا در allow {p}/{pr}: {r.get('error')}"}
    try:
        r = _run("--force", "enable", timeout=30)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return {"ok": False, "error": str(e)}
    st = status()
    if not st["active"]:
        return {"ok": False, "error": f"فعال‌سازی ناموفق بود: {out[:200]}"}
    return {"ok": True, "detail": out[:300]}


def disable() -> dict:
    if not installed():
        return {"ok": False, "error": "UFW نصب نیست"}
    try:
        r = _run("disable", timeout=30)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "detail": out[:300]}
