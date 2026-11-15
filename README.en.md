# 🚀 xpro — Secure VPN Deploy

[Русский](README.md) | **English**

![version](https://img.shields.io/badge/version-1.4.1-blue) ![platform](https://img.shields.io/badge/Debian%20%7C%20Ubuntu-supported-success)

An interactive bash script that installs and manages [3x-ui](https://github.com/MHSanaei/3x-ui) on Debian and Ubuntu.

All external traffic goes through a single port — 443. Nginx routes it by SNI and by path, while the panel, the subscription service and every connection listen on `127.0.0.1` only.

## ⚡ Installation

```bash
wget -4 -O xpro.sh https://raw.githubusercontent.com/sheijuro/xpro-deploy/main/xpro.sh && sudo bash xpro.sh
```

After the first run the menu is available from anywhere:

```bash
sudo xpro
```

The interface language (English or Russian) is chosen on the first run and can be changed in the menu: Server settings → Язык / Language.

## ✨ Features

- 🔒 **One port exposed.** Only SSH, 80 and 443 are open. Connection ports are unreachable from outside even with the firewall off.
- 🧩 **Flexible connections.** VLESS and Trojan over TCP, gRPC or XHTTP with Reality; TCP with its own TLS certificate; VLESS, Trojan and Shadowsocks over WebSocket, gRPC or XHTTP with TLS on the main domain.
- ➕ **As many connections as you need.** Add, change and delete them from the menu, no manual Nginx editing.
- 🔗 **Panel and subscription without ports in the URL.** HTTPS only, behind a secret path: `https://domain/secret-path/`.
- ✅ **Availability check.** After installation the script checks the panel, the dashboard and the subscription — directly and through Nginx — and shows what works and what does not.
- 🚀 **Fast 3x-ui download.** When GitHub is slow, the script switches to mirrors and resumes from the same point. A file from a mirror is accepted only if its SHA-256 checksum matches the one published by GitHub.
- 📜 **Let's Encrypt certificates** with automatic renewal.
- 🎭 **Decoy website.** One of ten built-in pages with a random site name; nothing is downloaded from the internet. Can be changed from the menu, or replaced with your own HTML.
- 👥 **Client management from the terminal.** Add and remove clients without opening the web panel.
- 🔄 **Safe updates.** The script, system packages and the panel are updated from the menu; your data is not touched.
- 🛡️ **Fail2ban.** Protects SSH and the website; port 443 is never banned, so VPN clients are not affected. Installs with or without the web dashboard.
- 📊 **Fail2ban dashboard.** Ban statistics in an OLED Black style behind a secret path, with no extra open port.
- 🌍 **GeoIP protection and whitelist.** The panel and dashboard open only from the allowed country and from trusted addresses. VPN and subscriptions stay reachable from any country.
- 🧯 **Mistake protection.** Irreversible actions require typing the word `yes`; a second simultaneous menu session is blocked.
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
| 1️⃣ | 🔐 Show access details: links to the panel, dashboard and subscription, the list of connections, saved logins and passwords |
| 2️⃣ | 👥 Manage users: the list of clients with their subscription links, add or remove a client |
| 3️⃣ | 🛠 Server settings: connections, decoy site, secret paths, Fail2ban, GeoIP, language, reinstall, full removal |
| 4️⃣ | 📊 Service status: Nginx, 3x-ui, Fail2ban, UFW, open ports, certificates and the availability check |
| 5️⃣ | 🔄 Updates: the script itself, system packages, the 3x-ui panel, the GeoIP database |

Before 3x-ui is installed, item 1 is "Install 3x-ui from scratch" and item 2 is hidden.

### Server settings

| Item | Action |
|---|---|
| 1 | Add a connection |
| 2 | Change a connection (protocol or transport) |
| 3 | Delete a connection |
| 4 | Change the decoy site to another built-in page |
| 5 | Install your own HTML for the decoy site |
| 6 | Change secret paths (panel, dashboard, subscription) |
| 7 | Fail2ban and the dashboard |
| 8 | GeoIP and whitelist |
| 9 | Язык / Language |
| 10 | Reinstall 3x-ui from scratch |
| 11 | Full removal of everything |

Updates do not touch your data: the 3x-ui database, Nginx and Fail2ban configs and certificates stay as they are. A new script version is checked on request under "Updates", not on every start.

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

- 🗑️ Reinstall and full removal erase the panel and the database with all clients. Both require typing the word `yes`; on reinstall a copy of the database is saved to `/root/`.
- 🌍 With GeoIP protection on, the panel will not open from another country unless your IP is whitelisted. You can turn it off over SSH: `sudo xpro` → Server settings → GeoIP.
- 🔑 Logins and passwords saved at installation are stored in `/root/xpro-summary.txt` and shown by item 1. Passwords are masked by default.
- 🧹 After changing the decoy site your browser may keep showing the previous page from its cache. Reload with Ctrl+Shift+R or open it in a private window.
- 🔄 An installation made by version 1.0.0 is not recognised: file names on the server have changed. Remove the old installation and install again.

## 📝 Changelog

See [Releases](https://github.com/sheijuro/xpro-deploy/releases).

## 📄 License

Distributed under the [GPL-3.0](LICENSE) license: you may use, modify and redistribute the script, but derived versions must stay open under the same license.

## 🙏 Projects used

- [3x-ui](https://github.com/MHSanaei/3x-ui) — Xray control panel, GPL-3.0
- [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite) — GeoIP database, CC BY 4.0
