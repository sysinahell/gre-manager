<div align="center">

# 🛰️ GRE Manager

**Terminal UI for IPv4 GRE tunnels, routes, NAT and backups on Debian / Ubuntu**

[![Version](https://img.shields.io/badge/version-1.4.0-blue.svg)](#-whats-new-in-v14)
[![Python](https://img.shields.io/badge/python-3.x-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-A81D33.svg?logo=debian&logoColor=white)](#-installation)
[![Tests](https://img.shields.io/badge/unit%20tests-42-success.svg)](test_gre_manager.py)
[![MikroTik](https://img.shields.io/badge/peer-MikroTik%20RouterOS-293239.svg)](#-example-new-gre-to-mikrotik)

**English** · [Русский](README.ru.md)

</div>

---

GRE Manager is a single-file Python + `dialog` TUI that runs comfortably over SSH. It manages GRE tunnels, routes, source-routing rules, backups, IP migration, per-tunnel Internet NAT and bulk firewall changes — and touches **only its own** GRE profiles stored in `/etc/gre-manager/tunnels/`.

## 📑 Contents

- [Features](#-features)
- [What's new in v1.4](#-whats-new-in-v14)
- [Installation](#-installation)
- [Example: new GRE to MikroTik](#-example-new-gre-to-mikrotik)
- [TUI: bulk NAT on/off](#-tui-bulk-nat-onoff)
- [CLI reference](#-cli-reference)
- [Verification](#-verification-on-the-linux-server)
- [Restore & IP migration](#-restore-to-another-server--mass-change-local-ipv4)
- [Safety & limitations](#-safety--limitations)
- [Testing](#-testing)

## ✨ Features

| | |
|---|---|
| 🧙 **Tunnel wizard** | Creates GRE with automatic `/30` allocation from a pool (default `10.255.10.0/24`) |
| 🌐 **Internet sharing** | Per-tunnel NAT + forwarding, enabled by default for new tunnels |
| 🔀 **Routing** | Return routes to LANs behind the peer, source-routing policy rules |
| 📦 **Bulk operations** | Enable/disable NAT on all or selected tunnels, live, without restarting GRE |
| 💾 **Backup / restore** | ZIP backups, automatic pre-change snapshots in `/var/backups/gre-manager/` |
| 🚚 **Migration** | Restore onto another server and mass-change the local underlay IPv4 |
| ⚙️ **systemd** | One `gre-manager@<tunnel>.service` instance per tunnel, optional autostart |
| 📟 **MikroTik hints** | Ready-to-paste RouterOS commands for the peer side |

## 🆕 What's new in v1.4

1. **NAT configured automatically for new GRE tunnels.** After you fill in the GRE endpoints, the wizard opens **Automatic Internet sharing** with `Enable Internet/NAT: yes` by default. The server WAN is suggested from the default Internet route, and the assigned `/30` GRE peer (`10.255.10.2/32`, etc.) is added to the allowed NAT sources. You can turn this off in the wizard.
2. **LANs behind MikroTik.** Optional comma-separated subnets in the same wizard, e.g. `192.168.88.0/24,192.168.99.0/24`. They are added to the NAT source allowlist **and** to the server GRE profile as return routes via that GRE interface (effective when the tunnel starts). LANs can't be inferred from the server — enter them manually.
3. **Start immediately.** After saving a new profile the wizard asks whether to enable autostart and start now. If yes, NAT / firewall / IP forwarding come up with the tunnel; if no, they're saved for the next start. A failed initial start disables autostart so a broken config doesn't keep retrying on reboot.
4. **Bulk Internet/NAT menu**, available from the main menu even when some tunnels are stopped: `ENABLE` / `DISABLE` for `ALL` or a multi-select checklist of tunnels (space toggles), followed by preview → auto-backup → confirmation → optional live apply.
5. **Live firewall switching.** NAT and forwarding rules can be toggled on running GRE **without restarting interfaces**. Rules are tracked per tunnel in `/run/gre-manager/`; on failure a best-effort rollback of configs and firewall rules is performed.
6. Editing the server-side GRE `/30` address also updates the allowlisted peer `/32` if it matched the previous peer. Other client LANs are not rewritten.
7. **Backward compatible.** Existing profiles and v1.2 / v1.3 backups keep working. Upgrading does **not** turn NAT on for existing profiles — use *Bulk Internet/NAT* to opt them in.

## 📥 Installation

### Dependencies

```bash
sudo apt update
sudo apt install -y python3 iproute2 iputils-ping dialog iptables procps
```

### Fresh install

```bash
git clone https://github.com/sysinahell/gre-manager.git
cd gre-manager
sudo install -m 0755 gre-manager.py /usr/local/sbin/gre-manager
sudo gre-manager init   # installs the systemd unit
sudo gre-manager        # launch the TUI
```

### Upgrade from v1.3

```bash
# optional but recommended
sudo gre-manager backup /root/gre-before-v14.zip

sudo cp -a /usr/local/sbin/gre-manager /usr/local/sbin/gre-manager.v1.3.bak
sudo install -m 0755 gre-manager.py /usr/local/sbin/gre-manager
sudo gre-manager
```

> [!NOTE]
> No need to restart networking or re-run `init` when replacing v1.3 — configurations are preserved.

## 🧭 Example: new GRE to MikroTik

| Parameter | Value |
|---|---|
| Server underlay IPv4 | `203.0.113.10` |
| MikroTik underlay IPv4 | `198.51.100.20` |
| Server WAN interface | `ens3` |
| GRE inner (server / MikroTik) | `10.255.10.1/30` / `10.255.10.2/30` |

**TUI:** `Create GRE tunnel` → enter `local`, `remote`, inner `/30` → `Automatic Internet sharing` → keep NAT `yes`, WAN `ens3`, optionally MikroTik LAN `192.168.88.0/24`.

The manager configures:

- server GRE address `10.255.10.1/30`;
- NAT allowlist `10.255.10.2/32` and (if supplied) `192.168.88.0/24`;
- return route `192.168.88.0/24 dev gre1` (if a LAN was supplied);
- IPv4 forwarding and per-GRE iptables rules at service start.

**On MikroTik:**

```routeros
/ip address add address=10.255.10.2/30 interface=GRE_NAME
```

> [!IMPORTANT]
> Keep the route to the server's **public underlay IP** outside the GRE tunnel. To reach the Internet from MikroTik/LAN through GRE, point routes / routing policy on MikroTik at the server's **inner GRE IP** (e.g. `10.255.10.1`). RouterOS is not configured automatically — `sudo gre-manager peer gre1` prints suggested commands.

## 📋 TUI: bulk NAT on/off

From the main menu:

```text
Bulk Internet/NAT: enable/disable ALL or selected GRE
    ENABLE  Internet NAT/forwarding
    DISABLE Internet NAT/forwarding

    ALL managed GRE tunnels
    Select specific GRE tunnels using checkboxes
         [ ] gre1
         [ ] gre2
         [ ] gre3
```

- When **enabling**, you may enter a common WAN override, or leave it blank to keep each tunnel's saved WAN (auto-detected if none).
- The preview lists every affected tunnel and any client-LAN routes still missing.
- Saving creates a backup in `/var/backups/gre-manager/`; active tunnels can be updated live, stopped ones pick up settings on next start.
- When **disabling**, tunnels and routes stay up. Recorded firewall rules are removed, but global IPv4 forwarding and its sysctl file are **left in place**, since other services may rely on them.

## 💻 CLI reference

```text
sudo gre-manager                         # interactive TUI
sudo gre-manager --help                  # usage
sudo gre-manager init                    # install systemd unit
sudo gre-manager backup /root/gre.zip    # save all managed GRE tunnels
sudo gre-manager pool [NEW_POOL_CIDR]    # show/change GRE /30 allocation pool
sudo gre-manager allocate [POOL_CIDR]    # preview next free server/client /30
sudo gre-manager peer TUNNEL             # RouterOS GRE IP/route instructions
sudo gre-manager internet TUNNEL         # show NAT/forwarding status
```

> [!TIP]
> `restore`, `bulk-local`, `internet` and `bulk-internet` are **preview-only** unless `--commit` is given.

### Bulk Internet NAT

```bash
# Preview only — changes nothing
sudo gre-manager bulk-internet --enable --all --wan ens3
sudo gre-manager bulk-internet --disable --tunnels gre1,gre3

# Commit and apply firewall rules immediately, without restarting GRE
sudo gre-manager bulk-internet --enable --all --wan ens3 --commit --apply
sudo gre-manager bulk-internet --disable --tunnels gre1,gre3 --commit --apply

# Save for the next service start/restart (no --apply)
sudo gre-manager bulk-internet --enable --tunnels gre1,gre2 --commit
```

> [!WARNING]
> For profiles that are already enabled, repeating `--enable --apply` with unchanged settings is a no-op. To apply staged changes, restart the GRE service or make an explicit setting change. In the TUI, choose live apply at the first commit for active tunnels.

### Single tunnel

```bash
sudo gre-manager internet gre1 --enable --wan ens3 \
  --sources 10.255.10.2/32,192.168.88.0/24 --commit --apply
```

For older profiles, make sure a route back to `192.168.88.0/24` via the GRE interface exists — bulk-enabling NAT doesn't add LAN routes to old profiles (the new-tunnel wizard does).

## 🔍 Verification on the Linux server

```bash
# GRE / link / routing state
ip -br -4 addr show
ip -4 route show
ip -d tunnel show

# IPv4 forwarding
sysctl net.ipv4.ip_forward

# NAT / FORWARD rules created by GRE Manager
sudo iptables -t nat -S POSTROUTING | grep gre-manager
sudo iptables -S FORWARD | grep gre-manager

# Service of tunnel gre1
sudo systemctl status gre-manager@gre1.service
sudo journalctl -u gre-manager@gre1.service -n 60 --no-pager
sudo gre-manager peer gre1
```

On MikroTik, check addresses and routes separately. `ping 10.255.10.1` from the router is the first check before routing LAN Internet traffic.

## 🚚 Restore to another server & mass-change local IPv4

```bash
sudo gre-manager backup /root/all-gre.zip
sudo gre-manager restore /root/all-gre.zip --local NEW_LOCAL_IP --wan ens3 --enable-saved --commit
sudo gre-manager bulk-local NEW_LOCAL_IP --from OLD_LOCAL_IP --commit --apply
```

- `restore` **never** starts tunnels, even when it restores autostart flags.
- `bulk-local --apply` **does** restart active GRE and may drop your SSH session.

## 🚧 Safety & limitations

- GRE is **IPv4 protocol 47**, not TCP/UDP port 47. Server and hosting firewalls must allow protocol 47 between the underlay peers. GRE is **not encrypted**.
- The NAT allowlist is bound to configured source CIDRs and the WAN device. **FORWARD** rules match the GRE input interface; **MASQUERADE** rules in `POSTROUTING` match source CIDR + WAN output (iptables doesn't allow `-i` there), so avoid overlapping client subnets and conflicting NAT rules. An unrestricted `0.0.0.0/0` source is **never** added.
- Other firewall layers (`nftables` base chains, UFW / firewalld, Docker, cloud security groups) can affect traffic — test real packet flow, not just rule presence.
- `net.ipv4.ip_forward=1` is persisted once NAT is enabled and is **not** reset when all NAT is disabled.
- Live changes touch only rules recorded by this manager and never flush chains. Rollback is **best-effort**, not a network transaction — keep console / out-of-band access.
- GRE devices managed by Netplan / NetworkManager / ifupdown are neither imported nor modified.

## 🧪 Testing

```bash
python3 -m unittest -v test_gre_manager.py
```

The script and its 42 unit tests have been verified syntactically and with mocks. A full end-to-end test on a real Debian/Ubuntu host with GRE and firewall has **not** been performed yet — please test in a safe environment first.

## 📂 Files

| Path | Purpose |
|---|---|
| `/usr/local/sbin/gre-manager` | Installed script |
| `/etc/gre-manager/tunnels/` | Managed GRE profiles |
| `/etc/gre-manager/settings.json` | Global settings (allocation pool) |
| `/etc/systemd/system/gre-manager@.service` | systemd template unit |
| `/etc/sysctl.d/90-gre-manager-forward.conf` | Persistent IPv4 forwarding |
| `/run/gre-manager/` | Runtime state, applied firewall rules |
| `/var/backups/gre-manager/` | Automatic pre-change backups |
