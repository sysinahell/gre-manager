<div align="center">

# 🛰️ GRE Manager

**Terminal UI for IPv4 GRE tunnels, routes, NAT, firewall and backups on Debian / Ubuntu**

[![Version](https://img.shields.io/badge/version-1.5.0-blue.svg)](#-whats-new-in-v15)
[![Status](https://img.shields.io/badge/status-pre--production-orange.svg)](#-safety--limitations)
[![Python](https://img.shields.io/badge/python-3.x-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-A81D33.svg?logo=debian&logoColor=white)](#-installation)
[![Tests](https://img.shields.io/badge/unit%20tests-62-success.svg)](#-testing)
[![MikroTik](https://img.shields.io/badge/peer-MikroTik%20RouterOS-293239.svg)](#-new-gre-to-mikrotik)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

[Русский](README.md) · **English**

</div>

---

GRE Manager is a single-file Python + `dialog` TUI that runs comfortably over SSH. It manages L3 GRE tunnels, routes, source routing, per-tunnel Internet NAT, firewall isolation, backups and IP migration — and touches **only its own** profiles in `/etc/gre-manager/tunnels/`.

Requires Python 3, `dialog`, `iproute2`, systemd and `iptables` (legacy or iptables-nft). GRETAP, IPv6 GRE, IPsec and GRE encryption are **not** supported.

> [!CAUTION]
> **Pre-production release.** Unit tests use mocks and fixtures; they don't replace a test run in a disposable Debian/Ubuntu VM against a real MikroTik. Never restart tunnel services over their only SSH connection without console / rescue access.

## 📑 Contents

- [Features](#-features)
- [What's new in v1.5](#-whats-new-in-v15)
- [Installation](#-installation)
- [New GRE to MikroTik](#-new-gre-to-mikrotik)
- [Firewall modes](#-firewall-modes)
- [Read-only host audit](#-read-only-host-audit)
- [Migrating existing GRE](#-migrating-existing-gre--two-phase-handover)
- [Bulk NAT & security](#-bulk-nat--security-mode)
- [Protocol-47 ingress ACL](#-optional-protocol-47-ingress-acl)
- [Firewall persistence](#-firewall-persistence--reconciliation)
- [Backups & IP migration](#-backups--ip-migration)
- [CLI reference](#-cli-reference)
- [Verification](#-verification)
- [Safety & limitations](#-safety--limitations)
- [Testing](#-testing)
- [License](#-license)

## ✨ Features

| | |
|---|---|
| 🧙 **Tunnel wizard** | Creates GRE with automatic `/30` allocation that checks live kernel addresses and routes |
| 🌐 **Internet sharing** | Per-tunnel NAT + forwarding, enabled by default for new tunnels |
| 🛡️ **Firewall isolation** | Dedicated `GMF_*` FORWARD chain per tunnel with explicit DROP |
| 🔒 **Ingress ACL** | Optional protocol-47 whitelist of GRE peers on the underlay IP |
| 🔎 **Audit** | Read-only report of legacy rules, address usage and unmanaged GRE |
| 🔁 **Migration** | Stage existing Linux GRE into managed profiles without touching them |
| 📦 **Bulk operations** | NAT and security mode for all or selected tunnels |
| 💾 **Backup / restore** | ZIP backups, automatic pre-change snapshots |
| ⚙️ **systemd** | One `gre-manager@<tunnel>.service` per tunnel, optional autostart |
| 📟 **MikroTik scripts** | Full RouterOS 6 / 7 config: GRE, routing table, mangle, address list, NAT |

## 🆕 What's new in v1.5

| Issue in 1.4 | v1.5 handling | Notes |
|---|---|---|
| `KeyError: internet` when editing the suggested `/30` | **Fixed**, covered by a test | The client `/32` follows the `/30` actually chosen |
| Existing Linux GRE weren't recognized | `stage-live` preview/staging + TUI | **No forced live takeover** — stop the old owner first |
| Pool only checked manager JSON | Reads kernel IPv4 addresses, all route tables, managed profiles and `/etc/gre-peers.conf` | Fails closed if the kernel can't be queried |
| Broad legacy ACCEPT / MASQUERADE bypassed the NAT toggle | Optional isolated FORWARD chain per GRE with terminal DROP | Old profiles stay `legacy` until changed |
| Existing custom FORWARD policies could be bypassed | `isolated-pass`: approved traffic RETURNs to the parent FORWARD chain | Default for staged GRE; new GRE use `isolated` |
| No restriction on who may send GRE | Optional protocol-47 INPUT ACL with peer whitelist + DROP | Explicit opt-in, single exclusive underlay scope |
| `iptables-persistent` restored duplicates | Identical manager rules are adopted idempotently | `firewall-reconcile` / `acl reconcile` if a reload flushes them |
| MTU 1476 / TTL 64 defaults | New GRE: **MTU 1400**, **TTL 250** | Existing profiles keep their values |
| Interfaces with both `/24` and `/30` | `extra_addresses` support; migration reads all IPv4 addresses | Verify duplicate-address behavior on your kernel |
| No bulk security change | `bulk-security` for all or selected tunnels | `--apply` **restarts** active GRE |

## 📥 Installation

### Dependencies

```bash
sudo apt-get update
sudo apt-get install -y python3 iproute2 dialog iptables iputils-ping procps
```

### Fresh install

```bash
git clone https://github.com/sysinahell/gre-manager.git
cd gre-manager
sudo install -m 0755 gre-manager.py /usr/local/sbin/gre-manager
sudo gre-manager init    # installs systemd units
sudo gre-manager audit   # read-only host check
sudo gre-manager         # launch the TUI
```

### Upgrade from v1.4

```bash
sudo gre-manager backup /root/gre-before-v15.zip
sudo cp -a /usr/local/sbin/gre-manager /usr/local/sbin/gre-manager.v1.4.bak
sudo install -m 0755 gre-manager.py /usr/local/sbin/gre-manager
sudo gre-manager init
sudo gre-manager audit
sudo gre-manager
```

> [!NOTE]
> `init` is required after upgrading: it creates the optional, **disabled-by-default** `gre-manager-input-acl.service`. It doesn't start or restart any GRE, and it won't overwrite a `gre-manager@.service` that differs from the known template.
>
> Replacing the Python file needs **no GRE restart**. Existing profiles stay `firewall_mode=legacy` until switched explicitly. Backups from v1.2–v1.4 remain readable.

## 🧭 New GRE to MikroTik

Typical topology: LAN → **source NAT on MikroTik to the GRE inner IP** → GRE → per-peer MASQUERADE on the server → Internet.

| Parameter | Value |
|---|---|
| Server inner GRE | `10.255.10.1/30` |
| MikroTik inner GRE | `10.255.10.2/30` |
| Defaults for new tunnels | MTU 1400, TTL 250, NAT on, `firewall_mode=isolated` |

- When MikroTik does the first NAT, **leave the MikroTik LANs field empty** in the wizard — the peer `/32` is allowed automatically and no return routes are needed.
- If LANs are routed without NAT, list them in the wizard: they're added to the NAT allowlist and as return routes via the GRE interface.
- The server WAN is auto-detected — double-check it on multihomed hosts.
- GRE (protocol 47) must be permitted in your existing INPUT firewall, unless you enable the [ingress ACL](#-optional-protocol-47-ingress-acl).

**On MikroTik:**

```routeros
/ip address add address=10.255.10.2/30 interface=GRE_NAME
```

> [!IMPORTANT]
> Keep the route to the server's **public underlay IP** outside the tunnel. RouterOS isn't configured automatically — `sudo gre-manager peer gre1` prints suggested commands.

### Full MikroTik script (RouterOS 6 / 7)

TUI: tunnel menu → `Generate full MikroTik script`. The result can be printed as plain text for mouse copy (no dialog borders), sent straight to your local clipboard via OSC 52 (Windows Terminal, iTerm2, kitty, WezTerm; tmux needs `set -g set-clipboard on`), saved as `.rsc` or viewed in a window. Or use the CLI:

```bash
sudo gre-manager mikrotik gre1 --ros 7 --clients 192.168.88.10,192.168.88.0/24
sudo gre-manager mikrotik gre1 --ros 6 --clients 192.168.88.10 -o /root/gre1.rsc
```

The script creates the GRE interface (keepalive off, MTU from the profile), its `/30` address, a separate routing table (`/routing table` on v7, `routing-mark` on v6) with a default route via the server's inner IP and `check-gateway=ping`, a client address list plus a bypass list for private networks, mangle (connection mark → routing mark, MSS clamp), masquerade into the tunnel and excludes marked connections from FastTrack. Only listed clients go through GRE; the router itself and the public GRE endpoint stay on the main table.

| Option | Meaning |
|---|---|
| `--ros 6\|7` | RouterOS version (default 7) |
| `--clients` | IPs / CIDRs routed into the tunnel |
| `--server-ip` | Server public IPv4, if the server is behind NAT |
| `--fallback` | No kill switch: clients use the main WAN while GRE is down |
| `-o FILE` | Save as `.rsc` for `/import` |

Every object is tagged `comment="gre-manager:<tunnel>"`; uninstall commands are at the end of the script.

## 🛡️ Firewall modes

| Mode | Behavior | Use for |
|---|---|---|
| `isolated` | Allows only listed sources to/from the selected WAN, drops all other FORWARD traffic of this GRE, adds source-scoped MASQUERADE | New tunnels (default) |
| `isolated-pass` | Allowed flows RETURN to the parent `FORWARD` chain so existing policies still decide | Coexistence with an existing firewall; default for staged GRE |
| `legacy` | Only manager NAT/FORWARD rules, no deny guard | Profiles from v1.4 and earlier |

New tunnels install their isolated guard **before** the GRE device comes up and remove it **after** it goes down, closing the window where a legacy `gre+ ACCEPT` could pass traffic.

> [!WARNING]
> On a fresh VPS with default FORWARD DROP, `isolated-pass` may need extra downstream ACCEPT rules. Other tools can later reorder FORWARD — run `audit` to check.

## 🔎 Read-only host audit

```bash
sudo gre-manager audit
```

Reports security mode and state of managed tunnels, legacy `gre+ ACCEPT`, non-manager MASQUERADE, gaps in manager chains/hooks, `/30` pool occupancy (kernel addresses + all routes + `/etc/gre-peers.conf`) and unmanaged kernel GRE. It **does not** parse arbitrary shell scripts or custom registries — review those manually.

Address conflict checks are strict: if an existing `/24` route or interface overlaps a proposed `/30`, the new tunnel is refused. Investigate rather than override.

## 🔁 Migrating existing GRE — two-phase handover

**1. Read-only scan and staging**

```bash
sudo gre-manager audit
sudo gre-manager stage-live gre-shop3           # preview only
sudo gre-manager stage-live gre-shop3 --commit  # create inactive profile, NEVER stops GRE
```

The preview reads live `ip -d -j link` parameters, all IPv4 addresses and non-connected routes via that GRE. The staged profile gets `internet.enabled=false`, `firewall_mode=isolated-pass` and no automatically attributed `ip rule`s. Complex definitions (wildcard remotes, asymmetric keys, unsupported parameters) are refused.

Before cutover, save existing policy routing, `iptables-save`, the original service / crontab and any legacy registry, and review the staged profile (addresses, keys, MTU, TTL, routes, WAN, NAT sources).

**2. Planned cutover** — only with console / rescue access:

1. Stop and disable the **old** owner and any auto-recreation; make sure it doesn't come back.
2. Delete the old kernel GRE interface.
3. `systemctl enable --now gre-manager@gre-shop3.service`.
4. Verify routes, packet captures and outbound NAT on both sides.

> [!WARNING]
> Never let an old script and the manager own the same interface at once. Broad legacy INPUT/FORWARD/NAT rules aren't removed automatically — plan that as a separate change. Migrate one test tunnel first; prefer `isolated-pass` until existing FORWARD checks are proven to still run.

## 📦 Bulk NAT & security mode

```bash
# Read-only previews until --commit
sudo gre-manager bulk-internet --enable --all --wan ens3
sudo gre-manager bulk-internet --disable --tunnels gre1,gre3

# NAT: firewall updated live, no GRE restart
sudo gre-manager bulk-internet --disable --tunnels gre1,gre3 --commit --apply

# Security mode: preview / save without restart
sudo gre-manager bulk-security --mode isolated-pass --tunnels gre1,gre2
sudo gre-manager bulk-security --mode isolated-pass --all --commit

# CAUTION: restarts active GRE (SSH may drop)
sudo gre-manager bulk-security --mode isolated-pass --all --commit --apply
```

In `isolated` / `isolated-pass`, turning NAT off keeps the manager's FORWARD deny guards. In `legacy`, it only removes manager rules — old broad ACCEPT/MASQUERADE may still pass traffic. `ip_forward` is global and is intentionally **never** auto-disabled.

## 🔒 Optional protocol-47 ingress ACL

**Not enabled on upgrade or migration.** Enable only on an **exclusive** underlay address after verifying that **all** live GRE on that IP are manager-owned. The ACL scopes `INPUT -i WAN -d LOCAL -p 47`, RETURNs known peer sources and DROPs all others.

```bash
sudo gre-manager acl preview --local 203.0.113.5 --wan ens3
sudo gre-manager acl enable  --local 203.0.113.5 --wan ens3 --exclusive-underlay --commit
sudo systemctl status gre-manager-input-acl.service

# after changing the peer list or an iptables reload
sudo gre-manager acl reconcile --commit

# remove only the manager's ACL
sudo gre-manager acl disable --commit
```

- One managed underlay scope per host. Activation is refused if an unmanaged or staged GRE is bound to that IP.
- Behind NAT, use the **server-assigned** local IP, not the public NAT address.
- Source-IP whitelisting is not authentication, integrity or encryption; approved packets still pass through your existing INPUT rules.

## 🧱 Firewall persistence & reconciliation

Manager rules use exact comments and dedicated `GMF_*` per-tunnel chains. If `netfilter-persistent` restores **identical** rules before the tunnel service starts, they're adopted without duplicates. If a later reload flushes them, the manager won't notice on its own:

```bash
sudo gre-manager audit
sudo gre-manager firewall-reconcile gre1
sudo gre-manager acl reconcile --commit   # only if the ingress ACL is on
```

`systemctl is-active` doesn't prove the firewall is correct. Reconciliation refuses externally modified manager chains, and no background timer is installed to avoid racing other firewall tools. In production pick **one firewall authority** and order reloads deliberately (netfilter-persistent / Docker / nftables / this manager).

## 💾 Backups & IP migration

```bash
sudo gre-manager backup /root/gre-export.zip
sudo gre-manager restore /root/gre-export.zip --local NEW_LOCAL --wan ens3
sudo gre-manager restore /root/gre-export.zip --local NEW_LOCAL --wan ens3 --enable-saved --commit

sudo gre-manager bulk-local NEW_LOCAL --from OLD_LOCAL
sudo gre-manager bulk-local NEW_LOCAL --from OLD_LOCAL --commit --apply
```

- `restore` **never** starts tunnels; `bulk-local --apply` **restarts** active GRE.
- Backups contain only manager profiles and enabled flags — **not** unmanaged tunnels, the global firewall, Docker, custom scripts / units or the ingress ACL. Migrate those separately.

## 💻 CLI reference

```text
sudo gre-manager                                   # interactive TUI
sudo gre-manager --help                            # usage
sudo gre-manager init                              # install systemd units
sudo gre-manager audit                             # read-only firewall / address audit
sudo gre-manager pool [NEW_POOL_CIDR]              # show/change /30 allocation pool
sudo gre-manager allocate [POOL_CIDR]              # preview next free /30
sudo gre-manager peer TUNNEL                       # RouterOS instructions
sudo gre-manager mikrotik TUNNEL [--ros 6|7] [--clients IPs] [--server-ip IPv4] [--fallback] [-o FILE]
sudo gre-manager internet TUNNEL [--enable|--disable] [--wan WAN] [--sources CIDRs] [--commit] [--apply]
sudo gre-manager bulk-internet --enable|--disable --all|--tunnels A,B [--wan WAN] [--commit] [--apply]
sudo gre-manager bulk-security --mode MODE --all|--tunnels A,B [--commit] [--apply]
sudo gre-manager stage-live NAME [--commit]        # stage an existing Linux GRE
sudo gre-manager firewall-reconcile NAME           # restore missing owned rules
sudo gre-manager acl preview|enable|disable|reconcile [...]
sudo gre-manager backup FILE.zip
sudo gre-manager restore FILE.zip [--local IPv4] [--replace] [--enable-saved] [--wan WAN] [--commit]
sudo gre-manager bulk-local NEW_IP [--from OLD_IP] [--allow-unassigned] [--commit] [--apply]
```

> [!TIP]
> Every state-changing command is **preview-only** until `--commit`.

## 🔍 Verification

```bash
ip -br -4 addr
ip -d tunnel show
ip -4 route show table all
ip -4 rule show
sudo iptables -S FORWARD
sudo iptables -t nat -S POSTROUTING
sudo iptables -S INPUT
sudo systemctl status gre-manager@gre1.service
sudo journalctl -u gre-manager@gre1.service -n 60 --no-pager
```

On MikroTik, `ping 10.255.10.1` is the first check before routing LAN traffic.

## 🚧 Safety & limitations

- GRE is **IPv4 protocol 47**, not TCP/UDP port 47, and it's **not encrypted**. Hosting/cloud firewalls must allow protocol 47 between underlay peers.
- MASQUERADE is matched by source CIDR + WAN output — avoid overlapping client subnets. An unrestricted `0.0.0.0/0` source is **never** added.
- Other layers (nftables base chains, UFW / firewalld, Docker, cloud security groups, reverse-path filtering) affect traffic — test real packet flow.
- Live changes only touch rules recorded by the manager and never flush chains. Rollback is **best-effort** — keep console / out-of-band access.
- GRE devices owned by Netplan / NetworkManager / ifupdown are not modified; existing ones can be brought under management only via `stage-live`.
- Validate duplicate inner prefixes, iptables-nft chains, Docker ordering, rp_filter and provider protocol-47 filtering in a disposable VM before production cutover.

## 🧪 Testing

```bash
python3 -m py_compile gre-manager.py
sudo python3 -m unittest discover -s tests -v
```

62 unit tests based on mocks / fixtures for iproute2, iptables and systemd. CLI tests need root (`sudo`). Live network-namespace / integration tests have **not** been run.

## 📂 Files

| Path | Purpose |
|---|---|
| `/usr/local/sbin/gre-manager` | Installed script |
| `/etc/gre-manager/tunnels/` | Managed GRE profiles |
| `/etc/gre-manager/settings.json` | Global settings (allocation pool) |
| `/etc/gre-manager/gre-input-acl.json` | Ingress ACL configuration |
| `/etc/gre-peers.conf` | Legacy peer registry (read-only, used for allocation) |
| `/etc/systemd/system/gre-manager@.service` | Per-tunnel template unit |
| `/etc/systemd/system/gre-manager-input-acl.service` | Ingress ACL unit (disabled by default) |
| `/etc/sysctl.d/90-gre-manager-forward.conf` | Persistent IPv4 forwarding |
| `/run/gre-manager/` | Runtime state, applied firewall rules |
| `/var/backups/gre-manager/` | Automatic pre-change backups |

## 📄 License

[MIT](LICENSE) © sysinahell
