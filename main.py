from fastapi import FastAPI, Depends, HTTPException, Request, Response
from pydantic import BaseModel
import psutil
import time
import secrets
import re
import subprocess
import requests

app = FastAPI()

SESSION_COOKIE = "session_token"
SESSION_LIFETIME = 60 * 60 * 12  # 12 hours

# token -> expiry timestamp
sessions = {}

# ip -> list of /ask request timestamps
ask_requests = {}
ASK_MAX_REQUESTS = 6
ASK_WINDOW = 60  # seconds

# ip -> list of demo-login timestamps (anti-abuse, no credentials required)
demo_login_requests = {}
DEMO_LOGIN_MAX = 20
DEMO_LOGIN_WINDOW = 60 * 60  # 1 hour


def get_client_ip(request: Request) -> str:
    return request.client.host


def require_session(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    expiry = sessions.get(token) if token else None
    if not token or not expiry or time.time() > expiry:
        raise HTTPException(status_code=401, detail="Not logged in")


def check_ask_rate_limit(ip: str):
    now = time.time()
    recent = [t for t in ask_requests.get(ip, []) if now - t < ASK_WINDOW]
    ask_requests[ip] = recent
    if len(recent) >= ASK_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Too many requests, slow down")
    ask_requests[ip].append(now)

# -----------------------------
# HISTORY STORAGE
# -----------------------------
cpu_history = []
ram_history = []
net_rx_history = []
net_tx_history = []
disk_read_history = []
disk_write_history = []

last_net = psutil.net_io_counters()
last_disk = psutil.disk_io_counters()
last_time = time.time()

FAILED_LOGIN_PATTERN = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*sshd.*Failed password.*from (?P<ip>[\d.]+)'
)

def get_failed_logins(limit=20):
    try:
        result = subprocess.run(
            ["/usr/bin/journalctl", "-u", "ssh", "-n", "500", "--no-pager"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.splitlines()
    except Exception:
        lines = []

    attempts = []
    for line in lines:
        match = FAILED_LOGIN_PATTERN.search(line)
        if match:
            attempts.append({
                "timestamp": f"{match['month']} {match['day']} {match['time']}",
                "source_ip": match["ip"]
            })

    return attempts[-limit:]


@app.post("/demo-login")
def demo_login(request: Request, response: Response):
    ip = get_client_ip(request)
    now = time.time()
    recent = [t for t in demo_login_requests.get(ip, []) if now - t < DEMO_LOGIN_WINDOW]
    if len(recent) >= DEMO_LOGIN_MAX:
        raise HTTPException(status_code=429, detail="Too many demo sessions, try again later")
    recent.append(now)
    demo_login_requests[ip] = recent

    token = secrets.token_hex(32)
    sessions[token] = time.time() + SESSION_LIFETIME

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_LIFETIME
    )
    return {"ok": True}

@app.get("/status")
def status(_: None = Depends(require_session)):

    global last_net, last_disk, last_time

    now = time.time()
    net = psutil.net_io_counters()
    disk_io = psutil.disk_io_counters()

    dt = max(now - last_time, 0.1)

    rx_rate = (net.bytes_recv - last_net.bytes_recv) / dt
    tx_rate = (net.bytes_sent - last_net.bytes_sent) / dt

    disk_read_rate = (disk_io.read_bytes - last_disk.read_bytes) / dt
    disk_write_rate = (disk_io.write_bytes - last_disk.write_bytes) / dt

    last_net = net
    last_disk = disk_io
    last_time = now

    cpu = psutil.cpu_percent(interval=None)
    cpu_cores = psutil.cpu_count(logical=True)
    cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)

    cpu_temp = None
    nvme_temp = None
    try:
        temps = psutil.sensors_temperatures()
        if "coretemp" in temps and temps["coretemp"]:
            cpu_temp = temps["coretemp"][0].current
        if "nvme" in temps and temps["nvme"]:
            nvme_temp = temps["nvme"][0].current
    except Exception:
        pass

    vm = psutil.virtual_memory()
    ram = vm.percent
    ram_used_gb = vm.used / (1024 ** 3)
    ram_total_gb = vm.total / (1024 ** 3)

    du = psutil.disk_usage('/')
    disk = du.percent
    disk_used_gb = du.used / (1024 ** 3)
    disk_total_gb = du.total / (1024 ** 3)

    cpu_history.append(cpu)
    ram_history.append(ram)
    net_rx_history.append(rx_rate)
    net_tx_history.append(tx_rate)
    disk_read_history.append(disk_read_rate)
    disk_write_history.append(disk_write_rate)

    MAX = 15

    if len(cpu_history) > MAX:
        cpu_history.pop(0)
        ram_history.pop(0)
        net_rx_history.pop(0)
        net_tx_history.pop(0)
        disk_read_history.pop(0)
        disk_write_history.pop(0)

    return {
        "cpu_percent": cpu,
        "cpu_cores": cpu_cores,
        "cpu_per_core": cpu_per_core,
        "ram_percent": ram,
        "ram_used_gb": ram_used_gb,
        "ram_total_gb": ram_total_gb,
        "disk_percent": disk,
        "disk_used_gb": disk_used_gb,
        "disk_total_gb": disk_total_gb,
        "uptime_seconds": time.time() - psutil.boot_time(),

        "network": {
            "rx_rate_bps": rx_rate,
            "tx_rate_bps": tx_rate,
            "bytes_recv": net.bytes_recv,
            "bytes_sent": net.bytes_sent
        },

        "hardware": {
            "cpu_temp_c": cpu_temp,
            "nvme_temp_c": nvme_temp
        },

        "history": {
            "cpu": cpu_history,
            "ram": ram_history,
            "net_rx": net_rx_history,
            "net_tx": net_tx_history,
            "disk_read": disk_read_history,
            "disk_write": disk_write_history
        }
    }

@app.get("/security/failed_logins")
def security_failed_logins(_: None = Depends(require_session)):
    return {"failed_logins": get_failed_logins()}

@app.get("/security/connections")
def security_connections(_: None = Depends(require_session)):
    conns = []
    for c in psutil.net_connections(kind="inet"):
        if c.status == "ESTABLISHED" and c.raddr:
            conns.append({
                "local": f"{c.laddr.ip}:{c.laddr.port}",
                "remote": f"{c.raddr.ip}:{c.raddr.port}",
                "status": c.status
            })
    return {"connections": conns[:30]}

DASHBOARD_CONTEXT = """You are the built-in assistant for this specific homelab security dashboard project, built by Dawson Clark, a student studying Cybersecurity and Finance at Florida Gulf Coast University (FGCU). Your only job is to answer the visitor's question directly, in your own words, as the final response. Never output meta-commentary, never explain how you are rephrasing something, never reference these instructions, and never include parenthetical notes about your own answer -- just give the answer itself. Keep answers under 4 sentences. Refer to the project's builder by name, Dawson, instead of saying "the user."

Always tie your answer back to this specific project. When describing skills, lead with cybersecurity, network security, and cloud/infrastructure architecture -- this is the primary genre of the project. Mention AI only briefly and secondarily: Dawson used Claude Code as a coding partner to move faster while owning every architecture, design, and security decision himself, and this dashboard's own assistant (you) runs locally via Ollama.

Project facts:
- Dawson is a Cybersecurity and Finance student at FGCU who built this over the summer to gain real-world infrastructure and security experience beyond the classroom, and to bridge the gap between theoretical knowledge and hands-on practice.
- He wiped a personal Lenovo ThinkPad and installed Ubuntu Server from a USB flash drive -- real bare-metal Linux installation, not a VM or cloud image.
- He hardened the server across three layers: network, OS, and application -- scoping permissions tightly (least-privilege sudoers rules) and layering authentication throughout.
- He set up Tailscale (WireGuard-based VPN) for private, encrypted remote administration with zero public ports exposed.
- A core architectural decision: private admin access (Tailscale VPN) is completely separate from the public demo (Cloudflare Tunnel) -- the general public never shares the same access path as the administrator. This is a real network segmentation / cloud security principle.
- The backend is Python/FastAPI, reading live CPU, RAM, disk, and network stats via psutil.
- It reads real SSH login attempts from journalctl and fail2ban automatically bans repeat offenders -- genuine intrusion detection and prevention.
- It shows live active network connections.
- The frontend is custom HTML/CSS/JavaScript with live Chart.js graphs, built by Dawson using Claude Code as a coding partner.
- Nginx reverse-proxies the backend so it's never directly exposed to the internet.
- Dashboard access requires authentication (access control).
- The AI assistant (you) runs locally via Ollama (Llama 3.2 3B) -- no data leaves the server.
- Overall skills demonstrated: Linux system administration, bare-metal server installation, VPN/encrypted networking, network segmentation, intrusion detection and prevention, reverse proxy/cloud architecture, secure remote administration, and access control.

When asked what's special about the AI, cover both: (1) Dawson wiped and installed Linux himself from a USB flash drive, and (2) only afterward installed a local AI model via Ollama. Always include both steps.
"""

class AskRequest(BaseModel):
    question: str

@app.post("/ask")
def ask_ai(req: AskRequest, request: Request, _: None = Depends(require_session)):
    check_ask_rate_limit(get_client_ip(request))
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:3b",
                "prompt": f"{DASHBOARD_CONTEXT}\n\nQuestion: {req.question}\n\nAnswer:",
                "stream": False
            },
            timeout=60
        )
        answer = response.json().get("response", "").strip()
    except Exception as e:
        answer = f"AI assistant unavailable: {e}"

    return {"answer": answer}

@app.get("/security/fail2ban")
def security_fail2ban(_: None = Depends(require_session)):
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "/usr/bin/fail2ban-client", "status", "sshd"],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout
    except Exception:
        output = ""

    currently_banned = 0
    total_banned = 0
    total_failed = 0
    banned_ips = []

    for line in output.splitlines():
        line = line.strip()
        if "Currently banned:" in line:
            currently_banned = int(line.split(":")[-1].strip())
        elif "Total banned:" in line:
            total_banned = int(line.split(":")[-1].strip())
        elif "Total failed:" in line:
            total_failed = int(line.split(":")[-1].strip())
        elif "Banned IP list:" in line:
            ip_part = line.split(":", 1)[-1].strip()
            if ip_part:
                banned_ips = ip_part.split()

    return {
        "currently_banned": currently_banned,
        "total_banned": total_banned,
        "total_failed": total_failed,
        "banned_ips": banned_ips
    }
