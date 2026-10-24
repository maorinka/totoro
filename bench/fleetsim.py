"""Simulate N persistent Wisp sensors over mTLS, speaking the agent's wire
protocol (hello + heartbeat lines). Each host records control commands it
receives into <outdir>/<host>.ctl so a test can see who a rollout reached.

usage: fleetsim.py N group outdir seconds [silent_host]
silent_host stops heartbeating after 1s (to exercise stale/decommission).
Environment: WISP_CONSOLE (ingest host:port, default 127.0.0.1:8750) and
WISP_PKI (directory with ca.crt, agent.crt, agent.key; default ../pki).
"""
import json, os, socket, ssl, sys, threading, time

N, group, outdir, secs = int(sys.argv[1]), sys.argv[2], sys.argv[3], float(sys.argv[4])
silent = sys.argv[5] if len(sys.argv) > 5 else None
root = os.path.dirname(os.path.abspath(__file__))
pki = os.environ.get("WISP_PKI") or os.path.join(root, "..", "pki")
chost, cport = os.environ.get("WISP_CONSOLE", "127.0.0.1:8750").rsplit(":", 1)
os.makedirs(outdir, exist_ok=True)


def ts():
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def host(i):
    name = f"{group}-{i:02d}"
    ctx = ssl.create_default_context(cafile=f"{pki}/ca.crt")
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT  # demo CA lacks keyUsage; the C agent accepts it
    ctx.load_cert_chain(f"{pki}/agent.crt", f"{pki}/agent.key")
    s = ctx.wrap_socket(socket.create_connection((chost, int(cport))), server_hostname="localhost")
    send = lambda o: s.sendall((json.dumps(o) + "\n").encode())
    send({"type": "hello", "host": name, "group": group, "version": "0.1.0",
          "host_id": f"id-{name}", "trust": "tpm" if i % 3 else "generated", "ephemeral": False})
    if i == 0:  # one host with an exploitable-looking alert history
        send({"ts": ts(), "type": "alert", "host": name, "group": group, "rule": "CRED-001",
              "severity": "high", "title": "ssh key read", "actor": "ai", "pid": 4242, "cmd": "cat ~/.ssh/id_rsa"})
    s.settimeout(0.2)
    got = []
    end = time.time() + secs
    nexthb = 0
    while time.time() < end:
        if time.time() >= nexthb and not (name == silent and time.time() > end - secs + 1):
            send({"ts": ts(), "type": "heartbeat", "host": name, "group": group, "execs": 10,
                  "cpu_pct": 0.01, "rss_kb": 7000, "mode": "monitor"})
            nexthb = time.time() + 0.5
        try:
            d = s.recv(4096)
            if d:
                got += [l for l in d.decode().splitlines() if l]
                open(f"{outdir}/{name}.ctl", "w").write("\n".join(got) + "\n")
        except (socket.timeout, ssl.SSLWantReadError):
            pass
    s.close()


ths = [threading.Thread(target=host, args=(i,)) for i in range(N)]
[t.start() for t in ths]
[t.join() for t in ths]
