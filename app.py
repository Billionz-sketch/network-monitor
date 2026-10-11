"""
Network Traffic Monitoring Server (client-server heartbeat design)

Clients (agent.py) check in every ~20s with their measured traffic stats.
The server aggregates them, detects presence (online/offline), raises alerts,
and queues admin commands that clients pick up on their next heartbeat.

Public visitors get a BASIC view (no IPs / hostnames / remote hosts).
After admin login they get the FULL view and can send commands.
"""
import os
import time
import hmac
import secrets
import threading
from collections import deque
from flask import Flask, jsonify, request, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=os.path.join(BASE, "static"), static_url_path="")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
CLIENT_KEY = os.environ.get("CLIENT_KEY", "")
LOCAL_DEV = False  # set in __main__

LOCK = threading.RLock()
clients = {}            # id -> dict
tokens = {}             # token -> expiry
events = deque(maxlen=200)
fleet_history = deque(maxlen=90)   # fleet snapshots, one per 5s
rules = {
    "bandwidth": {"label": "Bandwidth (KB/s)", "limit": 5000, "enabled": True},
    "latency":   {"label": "Latency (ms)",     "limit": 150,  "enabled": True},
    "loss":      {"label": "Packet loss (%)",  "limit": 5,    "enabled": True},
    "errors":    {"label": "Error rate (%)",   "limit": 2,    "enabled": True},
    "cpu":       {"label": "CPU (%)",          "limit": 90,   "enabled": True},
}
last_alert = {}   # (client_id, rule) -> ts
ALLOWED_CMDS = {"status", "shutdown", "cancel_shutdown", "logoff", "block_ip", "unblock_ip"}


def now():
    return time.time()


def log(level, msg, cid=None):
    events.appendleft({"t": now(), "level": level, "msg": msg, "client": cid})


def is_admin():
    tok = request.headers.get("X-Admin-Token", "")
    with LOCK:
        exp = tokens.get(tok)
        if exp and exp > now():
            return True
        tokens.pop(tok, None)
    return False


def num(v, d=0.0, lo=0.0, hi=1e12):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return d
    if v != v:
        return d
    return max(lo, min(hi, v))


def s(v, n=80):
    return str(v if v is not None else "")[:n]


def offline_after(c):
    return max(15, 3 * c.get("interval", 20))


def status_of(c):
    return "online" if now() - c["last_seen"] <= offline_after(c) else "offline"


def check_alerts(c):
    st = c["stats"]
    vals = {
        "bandwidth": st["bw_in"] + st["bw_out"],
        "latency": st["latency"] or 0,
        "loss": st["loss"],
        "errors": st["err_pct"],
        "cpu": st["cpu"],
    }
    for k, r in rules.items():
        if not r["enabled"]:
            continue
        v = vals[k]
        if v > r["limit"]:
            key = (c["id"], k)
            if now() - last_alert.get(key, 0) > 120:
                last_alert[key] = now()
                log("warn", f"{c['name']}: {r['label']} is {v:.1f} (limit {r['limit']})", c["id"])


# ---------------------------------------------------------------- API
@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    if CLIENT_KEY and not hmac.compare_digest(request.headers.get("X-Client-Key", ""), CLIENT_KEY):
        return jsonify(error="bad client key"), 401
    d = request.get_json(silent=True) or {}
    cid = s(d.get("client_id"), 32)
    if not cid:
        return jsonify(error="client_id required"), 400
    st = d.get("stats") or {}
    stats = {
        "bw_in": num(st.get("bw_in")), "bw_out": num(st.get("bw_out")),
        "pps": num(st.get("pps")), "err_pct": num(st.get("err_pct"), 0, 0, 100),
        "latency": (num(st.get("latency"), 0, 0, 60000) if st.get("latency") is not None else None),
        "loss": num(st.get("loss"), 0, 0, 100),
        "cpu": num(st.get("cpu"), 0, 0, 100), "mem": num(st.get("mem"), 0, 0, 100),
    }
    talkers = [{"host": s(t.get("host"), 60), "conns": int(num(t.get("conns")))}
               for t in (d.get("top_talkers") or [])[:8] if isinstance(t, dict)]
    protos = {s(k, 12): int(num(v)) for k, v in list((d.get("protocols") or {}).items())[:8]}
    with LOCK:
        c = clients.get(cid)
        first = c is None
        was_offline = (not first) and status_of(c) == "offline"
        if first:
            c = {"id": cid, "first_seen": now(), "queue": [], "history": deque(maxlen=60),
                 "results": deque(maxlen=20)}
            clients[cid] = c
        c.update(name=s(d.get("name")) or cid, hostname=s(d.get("hostname")), os=s(d.get("os"), 40),
                 ip=request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip(),
                 local_ip=s(d.get("ip"), 45),
                 interval=int(num(d.get("interval"), 20, 2, 600)), last_seen=now(), stats=stats,
                 top_talkers=talkers, protocols=protos, beats=c.get("beats", 0) + 1)
        c["history"].append({"t": now(), "bw": stats["bw_in"] + stats["bw_out"], "lat": stats["latency"]})
        for r in (d.get("results") or [])[:10]:
            if isinstance(r, dict):
                c["results"].appendleft({"t": now(), "cmd": s(r.get("cmd"), 20), "ok": bool(r.get("ok")),
                                         "msg": s(r.get("msg"), 200)})
                log("info" if r.get("ok") else "warn",
                    f"{c['name']} ran {s(r.get('cmd'), 20)}: {s(r.get('msg'), 120)}", cid)
        if first:
            log("info", f"New client registered: {c['name']}", cid)
        elif was_offline:
            log("info", f"{c['name']} is back online", cid)
        check_alerts(c)
        cmds, c["queue"] = c["queue"], []
    return jsonify(ok=True, commands=cmds, server_time=now())


@app.route("/api/login", methods=["POST"])
def login():
    if not ADMIN_PASSWORD:
        return jsonify(error="admin login is disabled (ADMIN_PASSWORD not set)"), 403
    pw = (request.get_json(silent=True) or {}).get("password", "")
    if not hmac.compare_digest(str(pw), ADMIN_PASSWORD):
        time.sleep(0.8)
        return jsonify(error="wrong password"), 401
    tok = secrets.token_urlsafe(24)
    with LOCK:
        tokens[tok] = now() + 8 * 3600
    log("info", "Admin signed in")
    return jsonify(token=tok)


@app.route("/api/logout", methods=["POST"])
def logout():
    with LOCK:
        tokens.pop(request.headers.get("X-Admin-Token", ""), None)
    return jsonify(ok=True)


def fleet_snapshot():
    on = [c for c in clients.values() if status_of(c) == "online"]
    lats = [c["stats"]["latency"] for c in on if c["stats"]["latency"] is not None]
    return {
        "t": now(), "total": len(clients), "online": len(on),
        "bw": sum(c["stats"]["bw_in"] + c["stats"]["bw_out"] for c in on),
        "latency": (sum(lats) / len(lats)) if lats else None,
    }


@app.route("/api/state")
def state():
    admin = is_admin()
    with LOCK:
        out = []
        for c in clients.values():
            item = {
                "id": c["id"], "name": c["name"], "os": c["os"], "status": status_of(c),
                "last_seen": c["last_seen"], "first_seen": c["first_seen"], "interval": c["interval"],
                "stats": c["stats"], "protocols": c["protocols"], "beats": c["beats"],
                "history": list(c["history"])[-30:],
            }
            if admin:
                item.update(hostname=c["hostname"], ip=c["ip"], local_ip=c["local_ip"],
                            top_talkers=c["top_talkers"], results=list(c["results"])[:5],
                            pending=len(c["queue"]))
            out.append(item)
        out.sort(key=lambda x: (x["status"] != "online", x["name"].lower()))
        evs = list(events)[:60]
        if not admin:
            evs = [e for e in evs if e["level"] != "info" or "Admin" not in e["msg"]]
        return jsonify(
            now=now(), admin=admin, clients=out, fleet=list(fleet_history), summary=fleet_snapshot(),
            events=evs, rules=rules,
            admin_enabled=bool(ADMIN_PASSWORD), key_required=bool(CLIENT_KEY),
        )


@app.route("/api/command", methods=["POST"])
def command():
    if not is_admin():
        return jsonify(error="admin login required"), 401
    d = request.get_json(silent=True) or {}
    cid, cmd = s(d.get("client_id"), 32), s(d.get("cmd"), 20)
    if cmd not in ALLOWED_CMDS:
        return jsonify(error="unknown command"), 400
    arg = {}
    if cmd == "shutdown":
        arg["delay"] = int(num(d.get("delay"), 60, 10, 3600))
    if cmd in ("block_ip", "unblock_ip"):
        ip = s(d.get("ip"), 45).strip()
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify(error="invalid IP address"), 400
        arg["ip"] = ip
    with LOCK:
        c = clients.get(cid)
        if not c:
            return jsonify(error="no such client"), 404
        if len(c["queue"]) >= 10:
            return jsonify(error="too many queued commands"), 429
        c["queue"].append({"cmd": cmd, **arg, "id": secrets.token_hex(4)})
        log("info", f"Admin queued '{cmd}' for {c['name']}", cid)
    return jsonify(ok=True, note="Queued. The client runs it on its next check-in.")


@app.route("/api/clients/<cid>", methods=["DELETE"])
def remove_client(cid):
    if not is_admin():
        return jsonify(error="admin login required"), 401
    with LOCK:
        c = clients.pop(cid, None)
        if c:
            log("info", f"Admin removed client {c['name']}")
    return jsonify(ok=bool(c))


@app.route("/api/rules", methods=["POST"])
def set_rules():
    if not is_admin():
        return jsonify(error="admin login required"), 401
    d = request.get_json(silent=True) or {}
    with LOCK:
        for k, v in d.items():
            if k in rules and isinstance(v, dict):
                if "limit" in v:
                    rules[k]["limit"] = num(v["limit"], rules[k]["limit"], 0, 1e9)
                if "enabled" in v:
                    rules[k]["enabled"] = bool(v["enabled"])
        log("info", "Admin updated alert rules")
    return jsonify(ok=True, rules=rules)


def base_url():
    proto = request.headers.get("X-Forwarded-Proto", request.scheme).split(",")[0].strip()
    return f"{proto}://{request.host}"


@app.route("/api/join-qr")
def join_qr():
    if not is_admin():
        return jsonify(error="admin login required"), 401
    from urllib.parse import quote
    from qr import make_svg
    url = base_url() + "/join.html" + (("?key=" + quote(CLIENT_KEY, safe="")) if CLIENT_KEY else "")
    return jsonify(url=url, svg=make_svg(url))


@app.route("/api/join-bat")
def join_bat():
    if not is_admin():
        return jsonify(error="admin login required"), 401
    from flask import Response
    server = base_url()
    key = CLIENT_KEY.replace("%", "%%").replace('"', "")
    lines = [
        "@echo off",
        "title Network Monitor Agent",
        f'set "SERVER={server}"',
        f'set "KEY={key}"',
        'cd /d "%~dp0"',
        "py --version >nul 2>nul",
        "if errorlevel 1 (",
        "  echo Python is not installed. Install it from https://www.python.org/downloads/ then run this file again.",
        "  pause",
        "  exit /b 1",
        ")",
        "echo Preparing the monitor agent, please wait...",
        "py -m pip install --quiet psutil",
        "powershell -NoProfile -Command \"Invoke-WebRequest -UseBasicParsing '%SERVER%/agent.py' -OutFile agent.py\"",
        "if not exist agent.py (",
        "  echo Could not download the agent. Check the internet connection.",
        "  pause",
        "  exit /b 1",
        ")",
        "echo Connected devices appear on the dashboard. Keep this window open.",
        'py agent.py --server "%SERVER%" --name "%COMPUTERNAME%" --key "%KEY%" --interval 20',
        "pause",
    ]
    r = Response("\r\n".join(lines) + "\r\n", mimetype="application/octet-stream")
    r.headers["Content-Disposition"] = 'attachment; filename="Join-Monitor.bat"'
    r.headers["Cache-Control"] = "no-store"
    return r


@app.route("/api/probe")
def probe():
    """64 KB payload so browser clients can measure their download speed."""
    from flask import Response
    r = Response(b"0" * 65536, mimetype="application/octet-stream")
    r.headers["Cache-Control"] = "no-store"
    return r


@app.route("/api/health")
def health():
    return jsonify(ok=True, clients=len(clients))


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ------------------------------------------------------- background
def monitor_loop():
    prev = {}
    while True:
        time.sleep(5)
        with LOCK:
            fleet_history.append(fleet_snapshot())
            for c in clients.values():
                st = status_of(c)
                if prev.get(c["id"]) == "online" and st == "offline":
                    log("warn", f"{c['name']} went offline (no check-in)", c["id"])
                prev[c["id"]] = st
            for t in [t for t, e in tokens.items() if e < now()]:
                tokens.pop(t, None)


_started = False


def start_background_threads():
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=monitor_loop, daemon=True).start()


start_background_threads()

if __name__ == "__main__":
    if not ADMIN_PASSWORD:
        ADMIN_PASSWORD = "admin"
        print("WARNING: ADMIN_PASSWORD not set; using 'admin' for local testing only.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), threaded=True)
