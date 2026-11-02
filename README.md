# 🕸️ NetMonitor

> **24/7 cross-platform network monitoring daemon.** Watch sockets, ports, adapters, VPNs, GeoIP, and full IP/domain intelligence — with **Discord & Telegram webhook alerts**, log export, backups, an HTTP API, Docker, and systemd support.

[![PyPI version](https://badge.fury.io/py/netmonitor.svg)](https://badge.fury.io/py/netmonitor)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/momalekiii/netmonitor/pulls)
[![GitHub stars](https://img.shields.io/github/stars/momalekiii/netmonitor?style=social)](https://github.com/momalekiii/netmonitor/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/momalekiii/netmonitor?style=social)](https://github.com/momalekiii/netmonitor/network/members)

---

## 🎯 What it does

| Category | Capability |
|----------|------------|
| **🔌 Sockets & Ports** | List all network connections (local/remote, status, PID, process). Filter by family (`tcp`, `udp`, `inet4`, `inet6`, `unix`, `all`) and status (`LISTEN`, `ESTABLISHED`, …). Check if a specific port is in use. |
| **👀 Watch Mode** | Live refreshing TUI (`netmonitor watch`) — like `htop` for network sockets. |
| **🔄 24/7 Daemon** | Background polling with change detection (`netmonitor daemon start`). Runs as a systemd service or Docker container. |
| **🧩 Adapters** | Every network interface: IP, MAC, status, speed, MTU, duplex, byte/packet counters, VPN flag. |
| **🔒 VPN Detection** | Auto-detects VPN/tunnel interfaces (`tun`, `tap`, `wg`, `ppp`, `ipsec`, `utun`, …). |
| **🌍 GeoIP** | Country, city, region, ISP/ASN, lat/long, timezone, currency for any IP — or your public IP. |
| **🌐 Domain/IP Details** | DNS resolution, reverse DNS, DNS records (A, AAAA, MX, NS, TXT, CNAME), WHOIS. |
| **🚨 Smart Alerts** | Port down/up, new connections, new countries (geo anomaly), configurable thresholds. Sent to Discord & Telegram. |
| **📤 Export Logs** | JSON / CSV / plain text with timestamps. |
| **💾 Backups** | ZIP any file or directory into timestamped archives. |
| **🔌 HTTP API** | `/status`, `/ports`, `/connections`, `/adapters`, `/vpn`, `/geoip/{ip}`, `/domain/{name}` (`netmonitor api`). |
| **📨 Webhooks** | Discord + Telegram message/alert delivery. |
| **🛡️ Security** | Port scan detection, brute-force detection, auto-block IPs, SSL cert checker, honeypots, security scorecard (0–100). |
| **📦 Deploy** | Docker, docker-compose, systemd unit, one-line install script. |

---

## 🚀 Quick Start

### Install from source

```bash
git clone https://github.com/momalekiii/netmonitor.git
cd netmonitor
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### Run the interactive menu

```bash
netmonitor
```

### Run as a 24/7 daemon (recommended for servers)

```bash
# Start background monitoring with alerts
netmonitor daemon start

# Check daemon status
netmonitor daemon status

# Stop the daemon
netmonitor daemon stop
```

### Or use individual commands

```bash
# See all sockets & ports
netmonitor ports

# Only listening ports
netmonitor ports --status LISTEN

# Check a specific port
netmonitor check 8080

# Live watch mode (refreshes every 5s)
netmonitor watch --interval 5

# List network adapters
netmonitor adapters

# Detect VPNs
netmonitor vpn

# GeoIP lookup
netmonitor geoip 8.8.8.8

# Full domain dossier
netmonitor domain example.com

# Configure alerts
netmonitor alerts

# Start HTTP API server
netmonitor api --port 8765

# Export logs
netmonitor export --label my-scan --format json

# Backup a folder
netmonitor backup ./my-folder --name weekly-backup

# Test webhooks
netmonitor webhook --test

# Send a custom alert
netmonitor webhook --message "🚨 Port 443 is down!" --level error

# Security scan with auto-block
netmonitor security-scan --auto-block

# Security scorecard
netmonitor security-score

# Block a suspicious IP
netmonitor security-block 1.2.3.4 --comment "port_scan"

# Check SSL cert expiry
netmonitor security-cert example.com

# Run honeypot on fake ports
netmonitor security-honeypot "2222,3333,4444" --duration 300

# Tunnel status & traffic
netmonitor tunnel-status
netmonitor tunnel-traffic
netmonitor tunnel
```

---

## 📨 Discord & Telegram Alerts

Configure once, get alerts forever.

```bash
netmonitor config
```

Or via environment variables:

```bash
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
export TELEGRAM_BOT_TOKEN="123456:ABC-DEF..."
export TELEGRAM_CHAT_ID="-1001234567890"
```

**Alert rules** (`netmonitor alerts`):
- Port down / port up
- New connections
- Geo anomaly (new countries)
- Custom known/safe country list

---

## 🛡️ Security Features

- **Port scan detection** — auto-block IPs hitting many ports
- **Brute-force detection** — auto-block IPs with repeated connections
- **Auto-block firewall** — nftables/iptables integration
- **SSL cert checker** — monitor certificate expiry
- **Honeypots** — fake listener ports that alert and block visitors
- **Security scorecard** — 0–100 grade with actionable findings

---

## 🐳 Docker Deployment

```bash
# Build and run
docker-compose up -d

# Or single container
docker build -t netmonitor .
docker run -d --net=host --cap-add NET_ADMIN --cap-add NET_RAW \
  -e DISCORD_WEBHOOK_URL=... \
  -v ./data/netmonitor:/root/.netmonitor \
  netmonitor daemon start
```

---

## 🖥️ systemd (Linux server)

```bash
sudo cp systemd/netmonitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netmonitor
sudo systemctl status netmonitor
```

Optional environment file at `/etc/default/netmonitor`:

```
DISCORD_WEBHOOK_URL=https://...
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
NETMONITOR_INTERVAL=60
```

---

## 📦 One-Command Install

```bash
curl -LsS https://raw.githubusercontent.com/momalekiii/netmonitor/main/install.sh | bash
```

Then: `netmonitor` or `netmonitor daemon start`.

---

## 🔌 HTTP API

Start with `netmonitor api` (default `http://127.0.0.1:8765`):

| Endpoint | Description |
|----------|-------------|
| `GET /` | Service health |
| `GET /status` | Daemon status + config |
| `GET /ports` | Listening ports |
| `GET /connections?kind=inet&status=LISTEN` | Active connections |
| `GET /adapters` | Network interfaces |
| `GET /vpn` | VPN/tunnel interfaces |
| `GET /geoip/{ip}` | GeoIP details |
| `GET /domain/{name}` | Full domain dossier |

---

## 📁 Project Structure

```
netmonitor/
├── netmonitor/
│   ├── __init__.py
│   ├── api.py          # HTTP API server (FastAPI)
│   ├── cli.py          # Typer CLI + interactive menu + watch + daemon + api + security + tunnel
│   ├── config.py       # JSON/YAML config + state persistence (~/.netmonitor)
│   ├── export.py       # JSON/CSV/TXT export + ZIP backups
│   ├── intel.py        # GeoIP, DNS, WHOIS, domain details
│   ├── monitor.py      # 24/7 daemon, change detection, geo anomaly alerts
│   ├── network.py      # Sockets, ports, adapters, VPN detection
│   ├── security.py     # Intrusion detection, auto-block, SSL, honeypots, scorecard
│   └── tunnel.py       # Tunnel core integration: config, process, ports, stats
├── tests/
├── systemd/
│   └── netmonitor.service
├── Dockerfile
├── docker-compose.yml
├── install.sh
├── README.md
├── LICENSE
├── pyproject.toml
└── requirements.txt
```

---

## 🤝 Contributing

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/amazing-thing`)
3. Commit your changes (`git commit -m 'Add amazing thing'`)
4. Push to the branch (`git push origin feature/amazing-thing`)
5. Open a Pull Request

---

## 📜 License

MIT License — see [LICENSE](LICENSE).

---

## 🚀 Help This Repo Trend

Want **NetMonitor** on GitHub Trending? Help us surge in the first 48–72 hours:

1. ⭐ **Star the repo** — stars are the #1 trending signal.
2. 🍴 **Fork it** — forks show adoption.
3. 🔁 **Share it** — Twitter/X, LinkedIn, Reddit (r/Python, r/networking, r/sysadmin, r/selfhosted), Discord, Telegram.
4. 🏷️ Add topics: `network-monitoring`, `cli-tool`, `daemon`, `geoip`, `discord-webhook`, `telegram-bot`, `sysadmin`, `docker`, `systemd`, `security`.
5. 🐛 Open issues & feature requests — engagement boosts visibility.
6. 🛠️ Submit PRs — multiple contributors = higher trending rank.
7. 📹 Post a demo GIF/asciinema of `netmonitor watch` in action.

A burst of stars, forks, and issues in a short window is what pushes repos into GitHub Trending. Share widely!

---

Made with ❤️ for sysadmins, network engineers, and security folks.
