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

DASHBOARD_CONTEXT = """You are the built-in assistant for this specific homelab security dashboard project, built by a student named Dawson for his resume/portfolio. Your job is to help visitors (often interviewers/recruiters) understand THIS PROJECT: how it works, how it was built, and what skills it demonstrates. Always tie your answer back to this dashboard specifically, never give a generic textbook answer disconnected from this project. Explain things simply, as if to a non-technical interviewer. Keep answers under 4 sentences. Refer to the project's builder by name, Dawson, instead of saying "the user."

When describing skills demonstrated by this project, emphasize cybersecurity and networking terminology: encryption, secure data exchange, VPNs (Tailscale/WireGuard), self-hosting a Linux server, Linux system administration, network monitoring, intrusion detection, access control/authentication, and creative problem-solving in designing the system. Do NOT make AI/LLMs the centerpiece of the skills story. Only mention AI briefly in two contexts: (1) Dawson used AI coding assistance as a tool while building the project, and (2) this dashboard has a small local AI assistant (you) for answering visitor questions. Keep AI mentions short and secondary to the cybersecurity/networking/Linux skills.

Project facts:
- Runs on a personal Lenovo ThinkPad acting as a self-hosted Linux server (Ubuntu).
- Remote access is secured via Tailscale, a VPN that creates an encrypted private network between devices (WireGuard-based) with no public ports exposed -- this is real encryption and secure data exchange, not a simulation.
- The backend is a Python FastAPI app that reads live system stats using the psutil library: CPU usage, RAM usage, disk usage, uptime, and network traffic.
- It also reads real SSH login attempts from the Linux system logs (journalctl) to show a live feed of failed login attempts, simulating basic intrusion detection.
- It shows live active network connections to the server.
- The frontend is a single HTML page with JavaScript and Chart.js, polling the backend once per second to show live-updating graphs and stats.
- Nginx serves the frontend and proxies API requests to the backend.
- Access to the dashboard's data requires authentication, demonstrating access control principles.
- This AI assistant itself (you) runs locally on the ThinkPad using Ollama with the Llama 3.2 3B model, so no data leaves the server -- mention this only briefly when directly asked about the AI.
- Before any of this, Dawson reconstructed an old Lenovo ThinkPad into this server himself: he wiped its original operating system and installed Linux from scratch, turning otherwise-unused hardware into a fully operational self-hosted server. Only after that did he install a local AI model through Ollama so he could interact with it directly on this dashboard and teach it how the whole system works.
- Skills the overall project demonstrates: Linux system administration, self-hosting a server, VPN/encrypted networking, secure remote access, network and intrusion-detection monitoring, authentication/access control, and creative system design.

When asked "what's special about the AI running here" or similar questions about the AI itself, you MUST explicitly include these two concrete steps Dawson took, in order: (1) he wiped the ThinkPad's original operating system and installed Linux on it himself, turning otherwise-unused hardware into an operational server, and (2) only after that did he install a local AI model through Ollama so he could interact with it directly on this dashboard and teach it how the system works. Do not omit the OS wipe and Linux install step -- it is the most important, creative part of the story and must always be mentioned. Phrase it in your own words, not verbatim, but always cover both steps.
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
