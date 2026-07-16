# Homelab Security Dashboard

A real-time server monitoring and security dashboard, self-hosted on a repurposed Lenovo ThinkPad running Ubuntu Server. Built from the ground up to demonstrate practical skills in Linux administration, network security, backend API development, and live data visualization.

> **Live Demo:** _coming soon_ &nbsp;·&nbsp; **Private access** secured over a WireGuard VPN

![Dashboard Screenshot](screenshots/dashboard.png)

---

## Overview

I installed Linux on an old Lenovo ThinkPad and built this server to learn how real infrastructure works and to demonstrate my skills. I wiped its original operating system, installed Ubuntu Server to turn otherwise-unused hardware into a fully operational, always-on Linux server, and hardened it across the network, OS, and application layers. On top of it I built a custom dashboard that reads live system and security metrics and displays them in real time — including an intrusion-detection feed and a locally-hosted AI assistant that answers questions about the project with no dependency on any cloud service.

Remote administration runs entirely over a Tailscale (WireGuard) VPN with no open ports, while the public demo is served through a Cloudflare Tunnel. I built the frontend — a custom HTML, CSS, and JavaScript interface with live Chart.js graphs — using Claude as a coding partner to design and refine it, while owning every architecture and security decision myself.

---

## Features

- **Live system metrics** — CPU, RAM, disk, network throughput, uptime, and hardware temperatures, updated once per second
- **Per-core CPU visualization** and real-time throughput graphs (Chart.js)
- **Intrusion detection feed** — parses the Linux system journal to display failed SSH login attempts as they happen
- **fail2ban integration** — shows currently banned IPs and total blocked attempts
- **Live network connections** — active established connections to the server
- **On-device AI assistant** — a local LLM (Ollama + Llama 3.2 3B) that answers questions about the project; no data ever leaves the server
- **Session-based authentication** with HttpOnly cookies and per-IP rate limiting

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
   Public visitor   │  Lenovo ThinkPad — Ubuntu Server         │
        │           │                                          │
        ▼           │   ┌──────────┐      ┌──────────────────┐ │
  Cloudflare Tunnel ─────►  Nginx   ├──────►  FastAPI/Uvicorn │ │
   (HTTPS, public)  │   │ (port 80)│      │  (port 8000,     │ │
                    │   │ reverse  │      │   internal only) │ │
        │           │   │  proxy   │      └────────┬─────────┘ │
        ▼           │   └──────────┘               │           │
  Private admin     │                    ┌─────────▼─────────┐ │
  over Tailscale ───────────────────────►│ psutil · journald │ │
   (WireGuard VPN)  │                    │ fail2ban · Ollama │ │
                    │                    └───────────────────┘ │
                    └─────────────────────────────────────────┘
```

- **Nginx** acts as a reverse proxy, isolating the application layer from direct exposure and providing a single controlled entry point (enables TLS termination and request filtering).
- The **FastAPI backend** is never exposed directly to the internet — it binds to `127.0.0.1:8000` and is only reachable through Nginx.
- **Remote admin access** runs over Tailscale (a WireGuard-based VPN) with **no public ports open** — real encrypted transport, not a simulation.
- The service is managed by **systemd** and restarts automatically on failure or reboot.

---

## Security Highlights (Defense in Depth)

| Layer | Control |
|-------|---------|
| **Transport** | WireGuard VPN (Tailscale) for private access; Cloudflare Tunnel provides TLS for the public demo — no inbound ports exposed on the host |
| **Application** | Session-based auth with HttpOnly cookies; rate limiting on the AI endpoint (6 req/min/IP) and demo sessions (20/hr/IP) |
| **Operating system** | fail2ban bans IPs after repeated failed SSH attempts; sudo privileges scoped to specific commands via `sudoers.d` |
| **Data** | The AI model runs entirely on-device (Ollama) — no user input or system data is sent to any third party |

---

## Tech Stack

- **Backend:** Python, FastAPI, Uvicorn, psutil
- **Frontend:** Vanilla HTML/CSS/JavaScript, Chart.js
- **Infrastructure:** Ubuntu Server, Nginx (reverse proxy), systemd
- **Networking / Security:** Tailscale (WireGuard), Cloudflare Tunnel, fail2ban
- **AI:** Ollama running Llama 3.2 3B, locally hosted

---

## What This Project Demonstrates

- Standing up and administering a Linux server from a bare-metal OS install
- Designing a production-style architecture (reverse proxy, internal-only app binding, process supervision)
- Applying layered security controls across the transport, application, and OS layers
- Building a backend API that interfaces directly with the operating system
- Self-hosting an AI model with zero cloud dependency
- End-to-end system design and creative problem-solving

---

_Built by Dawson Clark._
