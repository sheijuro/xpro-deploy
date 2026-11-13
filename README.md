# 🚀 xpro — Secure VPN Deploy

**English** | [Русский](README.ru.md)

![version](https://img.shields.io/badge/version-1.3.1-blue) ![platform](https://img.shields.io/badge/Debian%20%7C%20Ubuntu-supported-success)

An interactive bash script that installs and manages [3x-ui](https://github.com/MHSanaei/3x-ui) on Debian and Ubuntu.

All external traffic goes through a single port — 443. Nginx routes it by SNI and by path, while the panel, the subscription service and every connection listen on `127.0.0.1` only.

## ⚡ Installation

```bash
wget -O xpro.sh https://raw.githubusercontent.com/sheijuro/xpro-deploy/main/xpro.sh && sudo bash xpro.sh
```

After the first run the menu is available from anywhere:

```bash
sudo xpro
```

The interface language (English or Russian) is chosen on the first run and can be changed later in the menu.

## ✨ Features

- 🔒 **One port exposed.** Only SSH, 80 and 443 are open. Connection ports are unreachable from outside even with the firewall off.
- 🧩 **Flexible connections.** VLESS and Trojan over TCP, gRPC or XHTTP with Reality; TCP with its own TLS certificate; VLESS, Trojan and Shadowsocks over WebSocket, gRPC or XHTTP with TLS on the main domain.
- ➕ **As many connections as you need.** Add them or change protocol and transport from the menu, no manual Nginx editing.
- 🔗 **Panel and subscription without ports in the URL.** HTTPS only, behind a secret path: `https://domain/secret-path/`.
- 📜 **Let's Encrypt certificates** with automatic renewal.
- 🎭 **Decoy website.** A random ready-made template with a random site name on the main domain; can be changed from the menu.
- 👥 **Client management from the terminal.** Add and remove clients without opening the web panel.
- 🔄 **Safe updates.** The script, system packages and the panel are updated from the menu without touching your data.
- 🛡️ **Fail2ban.** Protects SSH and the website; port 443 is never banned, so VPN clients are not affected. Installs with or without the web dashboard.
- 📊 **Fail2ban dashboard.** Ban statistics in an OLED Black style behind a secret path, with no extra open port.
- 🌍 **GeoIP protection and whitelist.** The panel and dashboard open only from the allowed country and from trusted addresses. VPN and subscriptions stay reachable from any country.
- 🏳️ **Flag names.** A flag emoji is added by country: `🇫🇮 Finland`.
- 🌐 **Two languages.** English and Russian interface.
- ⌨️ **The `xpro` command.** The script installs itself into the system on the first run.

## 📋 Requirements

- 🖥️ Debian 12/13 or Ubuntu 22.04/24.04/26.04, root access
- 🌐 Two domains (or subdomains) with A records pointing to the server: the main one and one for Reality
- ➕ One extra domain for every additional Reality or TCP+TLS connection
- 📡 IPv4 access to the server — IPv6 is disabled during installation

## 🧭 Menu

| Item | Action |
|---|---|
| 1️⃣ | 🔐 Show access details: links, all connections and clients with their subscription links (read live from the panel database) |
| 2️⃣ | 👥 Manage users: add or remove a client |
| 3️⃣ | 🛠 Server settings: add or change connections, change the decoy site, rotate secret paths, Fail2ban, GeoIP, language, reinstall, full removal |
| 4️⃣ | 📊 Service status: Nginx, 3x-ui, Fail2ban, UFW, open ports, certificates |
| 5️⃣ | 🔄 Updates: the script itself, system packages, the 3x-ui panel, the GeoIP database |

Before 3x-ui is installed, item 1 is «Install 3x-ui from scratch» and item 2 is hidden.

Updates never touch your data: the 3x-ui database, Nginx and Fail2ban configs and certificates stay as they are.

## 🔌 Connection types

| Transport | Security | Protocols | Needs its own domain |
|---|---|---|---|
| TCP, gRPC, XHTTP | Reality | VLESS, Trojan | yes |
| TCP | TLS (own certificate) | VLESS, Trojan | yes |
| WebSocket, gRPC, XHTTP | TLS via Nginx | VLESS, Trojan, Shadowsocks | no |

## 🏗️ How it works

```
Internet ──443──> Nginx (stream, SNI)
    ├─ domain of a Reality / TCP+TLS connection ──> 127.0.0.1:<port>  (Xray)
    └─ main domain                              ──> Nginx HTTPS
          ├─ /secret/  → 3x-ui panel           (GeoIP)
          ├─ /secret/  → Fail2ban dashboard    (GeoIP)
          ├─ /secret/  → subscription
          ├─ /path     → WebSocket / gRPC / XHTTP connections
          └─ /         → decoy website
```

The GeoIP check applies to the panel and the dashboard only. Subscriptions and VPN connections are never affected.

## ⚠️ Important

- 🗑️ Item 1 on a server that already has 3x-ui removes the existing panel and database. A copy of the database is saved to `/root/`.
- 🌍 With GeoIP protection on, the panel will not open from another country unless your IP is whitelisted. You can turn it off over SSH: `sudo xpro` → Server settings → GeoIP.
- 🔑 Logins and passwords saved at installation are stored in `/root/xpro-summary.txt` and shown by item 1. Passwords are masked by default.
- 🔄 An installation made by version 1.0.0 is not recognised: file names on the server have changed. Remove the old installation and install again.

## 📝 Changelog

See [Releases](https://github.com/sheijuro/xpro-deploy/releases).

## 🙏 Projects used

- [3x-ui](https://github.com/MHSanaei/3x-ui) — Xray control panel, GPL-3.0
- [Start Bootstrap](https://github.com/StartBootstrap) — decoy website templates, MIT
- [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite) — GeoIP database, CC BY 4.0
