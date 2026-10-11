"""
Network Monitor client agent.

Runs on a staff laptop. Every --interval seconds (default 20) it measures local
network traffic and "checks in" (heartbeat) with the central server. The server
may reply with admin commands (shutdown, logoff, block IP...), which the agent
runs and reports back on the next check-in.

Usage:
  pip install psutil
  python agent.py --server https://YOUR-APP.onrender.com --name "Accounts PC" --key YOURKEY
Options: --interval 20  --id custom-id  --dry-run (never run commands)
         --no-commands  --allow-private-block
"""
import argparse, hashlib, ipaddress, json, platform, re, socket, subprocess, sys, time, uuid
import urllib.request, urllib.error
from collections import Counter

try:
    import psutil
except ImportError:
    sys.exit("psutil is missing. Run:  pip install psutil")

IS_WIN = platform.system() == "Windows"


def client_id():
    return hashlib.sha1(f"{platform.node()}{uuid.getnode()}".encode()).hexdigest()[:12]


def local_ip():
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.connect(("8.8.8.8", 80))
        ip = sk.getsockname()[0]
        sk.close()
        return ip
    except Exception:
        return ""


def ping(host="8.8.8.8", count=3):
    """Return (avg_latency_ms or None, loss_pct) using the OS ping command."""
    cmd = ["ping", "-n", str(count), "-w", "1500", host] if IS_WIN else ["ping", "-c", str(count), "-W", "2", host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return None, 100.0
    loss = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s*)?loss", out, re.I)
    loss = float(loss.group(1)) if loss else 100.0
    avg = re.search(r"Average\s*=\s*(\d+)\s*ms", out) or re.search(r"=\s*[\d.]+/([\d.]+)/", out)
    return (float(avg.group(1)) if avg else None), loss


def top_hosts(n=6):
    c = Counter()
    protos = Counter()
    try:
        for k in psutil.net_connections(kind="inet"):
            if k.raddr and k.status == "ESTABLISHED":
                c[k.raddr.ip] += 1
                p = {80: "HTTP", 443: "HTTPS", 3389: "RDP", 22: "SSH", 53: "DNS"}.get(k.raddr.port, "TCP" if k.type == socket.SOCK_STREAM else "UDP")
                protos[p] += 1
    except Exception:
        pass
    return [{"host": h, "conns": v} for h, v in c.most_common(n)], dict(protos)


class Sampler:
    def __init__(self):
        self.prev = psutil.net_io_counters()
        self.t = time.time()
        psutil.cpu_percent(None)

    def sample(self):
        cur, t = psutil.net_io_counters(), time.time()
        dt = max(t - self.t, 0.001)
        p = self.prev
        pk = (cur.packets_recv + cur.packets_sent) - (p.packets_recv + p.packets_sent)
        er = (cur.errin + cur.errout + cur.dropin + cur.dropout) - (p.errin + p.errout + p.dropin + p.dropout)
        s = {
            "bw_in": round((cur.bytes_recv - p.bytes_recv) / dt / 1024, 1),
            "bw_out": round((cur.bytes_sent - p.bytes_sent) / dt / 1024, 1),
            "pps": round(pk / dt, 1),
            "err_pct": round(100 * er / pk, 2) if pk > 0 else 0,
            "cpu": psutil.cpu_percent(None),
            "mem": psutil.virtual_memory().percent,
        }
        self.prev, self.t = cur, t
        return s


def run(cmd, dry):
    if dry:
        return True, "DRY-RUN: " + " ".join(cmd)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        msg = (r.stdout or r.stderr or "").strip()[:150] or f"exit code {r.returncode}"
        return r.returncode == 0, msg
    except Exception as e:
        return False, str(e)[:150]


def own_ips():
    ips = {"127.0.0.1", "::1"}
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            ips.add(a.address.split("%")[0])
    return ips


def safe_ip(ip, allow_private):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False, "invalid IP"
    if a.is_loopback or a.is_unspecified or a.is_multicast:
        return False, "refused: loopback/unspecified address"
    if ip in own_ips():
        return False, "refused: that is this machine's own address"
    if (a.is_private or a.is_link_local) and not allow_private:
        return False, "refused: private/LAN address (start agent with --allow-private-block to allow)"
    return True, ""


def execute(c, args):
    cmd, dry = c.get("cmd"), args.dry_run
    if args.no_commands:
        return False, "commands disabled on this client"
    if cmd == "status":
        return True, f"cpu {psutil.cpu_percent(None)}% mem {psutil.virtual_memory().percent}% host {platform.node()}"
    if cmd == "shutdown":
        d = int(c.get("delay", 60))
        return run(["shutdown", "/s", "/t", str(d)] if IS_WIN else ["shutdown", "-h", f"+{max(1, d // 60)}"], dry)
    if cmd == "cancel_shutdown":
        return run(["shutdown", "/a"] if IS_WIN else ["shutdown", "-c"], dry)
    if cmd == "logoff":
        return run(["shutdown", "/l"] if IS_WIN else ["loginctl", "terminate-user", psutil.Process().username()], dry)
    if cmd in ("block_ip", "unblock_ip"):
        ip = c.get("ip", "")
        ok, why = safe_ip(ip, args.allow_private_block)
        if not ok:
            return False, why
        name = f"NetMon-{ip}"
        if IS_WIN:
            if cmd == "block_ip":
                ok1, m1 = run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=out", "action=block", f"remoteip={ip}"], dry)
                ok2, m2 = run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=block", f"remoteip={ip}"], dry)
                return ok1 and ok2, m1 if not ok1 else f"blocked {ip}"
            return run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], dry)
        flag = "-I" if cmd == "block_ip" else "-D"
        ok1, m1 = run(["iptables", flag, "OUTPUT", "-d", ip, "-j", "DROP"], dry)
        return ok1, m1
    return False, "unknown command"


def post(url, payload, key, timeout):
    req = urllib.request.Request(url, json.dumps(payload).encode(), {"Content-Type": "application/json", "X-Client-Key": key})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def main():
    ap = argparse.ArgumentParser(description="Network Monitor client agent")
    ap.add_argument("--server", required=True)
    ap.add_argument("--name", default=platform.node())
    ap.add_argument("--key", default="")
    ap.add_argument("--interval", type=int, default=20)
    ap.add_argument("--id", default=client_id())
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-commands", action="store_true")
    ap.add_argument("--allow-private-block", action="store_true")
    args = ap.parse_args()
    url = args.server.rstrip("/") + "/api/heartbeat"
    sam, results = Sampler(), []
    print(f"Agent '{args.name}' (id {args.id}) -> {args.server} every {args.interval}s"
          + ("  [DRY-RUN]" if args.dry_run else ""))
    while True:
        lat, loss = ping()
        stats = sam.sample()
        stats.update(latency=lat, loss=loss)
        talkers, protos = top_hosts()
        payload = {"client_id": args.id, "name": args.name, "hostname": platform.node(),
                   "os": f"{platform.system()} {platform.release()}", "ip": local_ip(),
                   "interval": args.interval, "stats": stats, "top_talkers": talkers,
                   "protocols": protos, "results": results}
        try:
            reply = post(url, payload, args.key, 60)
            results = []
            cmds = reply.get("commands", [])
            print(time.strftime("%H:%M:%S"), f"check-in ok  bw {stats['bw_in'] + stats['bw_out']:.0f} KB/s  lat {lat}  loss {loss}%  cmds {len(cmds)}")
            for c in cmds:
                ok, msg = execute(c, args)
                print("   command", c.get("cmd"), "->", "OK" if ok else "FAILED", msg)
                results.append({"cmd": c.get("cmd"), "ok": ok, "msg": msg})
            if cmds:
                time.sleep(1)
                continue   # report results immediately
        except urllib.error.HTTPError as e:
            print("server rejected check-in:", e.code, "(wrong --key?)" if e.code == 401 else "")
        except Exception as e:
            print("cannot reach server (will retry):", str(e)[:100])
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAgent stopped.")
