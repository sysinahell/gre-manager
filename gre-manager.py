#!/usr/bin/env python3
"""GRE Manager v1.5: an SSH-friendly dialog UI for IPv4 GRE tunnels on Linux.

Persistent configuration is deliberately independent of Netplan,
NetworkManager and ifupdown. Only interfaces configured by this utility
are managed. Requires: Python 3, iproute2, systemd, dialog (for UI).
"""

import argparse
import copy
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

VERSION = "1.5.0"
BASE = Path("/etc/gre-manager/tunnels")
STATE = Path("/run/gre-manager")
BACKUP_DIR = Path("/var/backups/gre-manager")
SETTINGS_PATH = Path("/etc/gre-manager/settings.json")
FORWARD_SYSCTL = Path("/etc/sysctl.d/90-gre-manager-forward.conf")
DEFAULT_POOL = "10.255.10.0/24"
LEGACY_PEERS = Path("/etc/gre-peers.conf")
ACL_PATH = Path("/etc/gre-manager/gre-input-acl.json")
ACL_UNIT = Path("/etc/systemd/system/gre-manager-input-acl.service")
ACL_RUNTIME = Path("/run/gre-manager/input-acl.json")
BACKUP_MAGIC = "gre-manager-managed-tunnels"
BACKUP_SCHEMA = 1
UNIT_PATH = Path("/etc/systemd/system/gre-manager@.service")
BIN_PATH = "/usr/local/sbin/gre-manager"
NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$")
IFNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}$")
SERVICE = f"""[Unit]
Description=GRE Manager tunnel %i
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={BIN_PATH} _up %i
ExecStop={BIN_PATH} _down %i
TimeoutStartSec=30
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
"""


ACL_SERVICE = f"""[Unit]
Description=GRE Manager optional public-underlay peer whitelist
Wants=network-online.target
After=network-online.target netfilter-persistent.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={BIN_PATH} _acl_restore
ExecStop={BIN_PATH} _acl_clear
TimeoutStartSec=30
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
"""


class GreError(Exception):
    pass


def run(args, check=True):
    p = subprocess.run(args, universal_newlines=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=False)
    if check and p.returncode != 0:
        raise GreError(f"$ {' '.join(args)}\n{p.stderr.strip() or p.stdout.strip()}")
    return p


def ip4(value, label):
    try:
        a = ipaddress.IPv4Address(str(value).strip())
    except ValueError as e:
        raise GreError(f"{label}: {e}")
    if a.is_multicast or a.is_unspecified or a.is_loopback:
        raise GreError(f"{label}: unusable IPv4 address")
    return str(a)


def network(value, label):
    try:
        return str(ipaddress.IPv4Network(str(value).strip(), strict=False))
    except ValueError as e:
        raise GreError(f"{label}: {e}")


def table_id(value):
    value = str(value).strip()
    if value == "main":
        return value
    if not value.isdecimal() or not (1 <= int(value) <= 4294967295):
        raise GreError("Routing table must be 'main' or a positive numeric ID")
    if int(value) in (253, 254, 255):
        raise GreError("Use 'main' for table 254; 253 and 255 are reserved")
    return str(int(value))


def pool_validate(cidr):
    try:
        pool = ipaddress.IPv4Network(str(cidr).strip(), strict=True)
    except ValueError as e:
        raise GreError(f"GRE address pool: {e}") from e
    if pool.prefixlen < 16 or pool.prefixlen > 30 or not pool.is_private:
        raise GreError("GRE /30 pool must be a private IPv4 network between /16 and /30")
    return str(pool)


def read_pool():
    if not SETTINGS_PATH.exists():
        return DEFAULT_POOL
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        return pool_validate(data["pool"])
    except (ValueError, KeyError, TypeError) as e:
        raise GreError(f"Invalid GRE Manager settings: {e}") from e


def write_pool(cidr):
    cidr = pool_validate(cidr)
    SETTINGS_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix=".gre-settings-", dir=SETTINGS_PATH.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"pool": cidr}, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(path, 0o600)
        os.replace(path, SETTINGS_PATH)
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return cidr


def peer_address(c):
    """Other usable GRE endpoint in a /30; return '' for other masks."""
    iface = ipaddress.IPv4Interface(c["address"])
    if iface.network.prefixlen != 30:
        return ""
    other = [x for x in iface.network.hosts() if x != iface.ip]
    return str(other[0]) if len(other) == 1 else ""


def external_address_occupancy(pool, exclude_device=""):
    """Inventory kernel IPv4 addresses, routes and parseable legacy CIDRs.

    Each record is (IPv4Network, evidence). If the kernel inventory cannot be
    queried reliably, allocation refuses to guess that an address is free.
    """
    scope = ipaddress.IPv4Network(pool_validate(pool))
    used = []
    def add(value, evidence):
        try:
            item = ipaddress.IPv4Network(str(value), strict=False)
            if item.overlaps(scope):
                used.append((item, evidence))
        except ValueError:
            pass
    for name in names():
        c = load(name)
        for addr in [c["address"]] + c.get("extra_addresses", []):
            add(ipaddress.IPv4Interface(addr).network, f"managed:{name}")
    commands = [(["ip", "-j", "-4", "addr", "show"], "kernel-addresses"),
                (["ip", "-j", "-4", "route", "show", "table", "all"], "kernel-routes")]
    for command, evidence in commands:
        result = run(command, check=False)
        if result.returncode != 0:
            raise GreError(f"Cannot audit {evidence}; refusing automatic GRE IP allocation: "
                           f"{result.stderr.strip()}")
        try:
            rows = json.loads(result.stdout)
            if not isinstance(rows, list):
                raise ValueError("expected JSON list")
        except (ValueError, TypeError) as e:
            raise GreError(f"Cannot parse {evidence}; refusing allocation: {e}") from e
        for entry in rows:
            if not isinstance(entry, dict):
                continue
            if entry.get("dev") == exclude_device or entry.get("ifname") == exclude_device:
                continue
            if evidence == "kernel-addresses":
                for addr in entry.get("addr_info", []):
                    if addr.get("family") == "inet" and addr.get("local"):
                        add(f"{addr['local']}/{addr['prefixlen']}",
                            f"interface:{entry.get('ifname', '?')}")
            else:
                dst = entry.get("dst", "default")
                if dst != "default" and dst:
                    add(dst, f"route:{entry.get('dev', '?')}:{entry.get('table', 'main')}")
    if LEGACY_PEERS.exists():
        # Legacy records are not standardized. Extract only explicit IPv4 CIDRs;
        # audit warns that bare IPs/other scripts require manual migration review.
        contents = LEGACY_PEERS.read_text(encoding="utf-8", errors="replace")
        for entry in re.findall(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![0-9./])", contents):
            # Bare legacy IPv4: conservatively reserve at least its /32.
            add(entry if "/" in entry else entry + "/32", f"legacy:{LEGACY_PEERS}")
    return used


def address_conflicts(address, exclude_name="", extra=()):
    """Report networks that collide with the candidate GRE subnet."""
    candidate = ipaddress.IPv4Interface(address).network
    # A /30 is inside the allocator pool; if outside, still scan the complete
    # host inventory with a host-specific audit scope.
    scope = str(candidate)
    if candidate.prefixlen > 30:
        scope = str(ipaddress.IPv4Network(f"{candidate.network_address}/30", strict=False))
    matches = external_address_occupancy(scope, exclude_device=exclude_name)
    return [(str(n), evidence) for n, evidence in matches
            if n.overlaps(candidate) and evidence != f"managed:{exclude_name}"]


def allocate_pair(pool, existing=None):
    """Choose /30 after checking managed and unmanaged host address usage."""
    pool = ipaddress.IPv4Network(pool_validate(pool))
    if existing is None:
        occupancy = external_address_occupancy(str(pool))
        used = [n for n, _ in occupancy]
    else:
        used = [ipaddress.IPv4Network(str(n), strict=False) for n in existing]
    for subnet in pool.subnets(new_prefix=30) if pool.prefixlen < 30 else (pool,):
        if all(not subnet.overlaps(n) for n in used):
            server, client = tuple(subnet.hosts())
            return {"network": str(subnet), "server": f"{server}/30",
                    "peer": f"{client}/30"}
    raise GreError(f"No unused /30 networks remain in {pool}")


def normalize_internet(raw):
    raw = raw or {}
    if not isinstance(raw, dict):
        raise GreError("Internet/NAT settings must be an object")
    enabled = raw.get("enabled", False)
    if type(enabled) is not bool:
        raise GreError("NAT enabled must be true or false")
    wan = str(raw.get("wan", "")).strip()
    if wan and not IFNAME_RE.fullmatch(wan):
        raise GreError("WAN interface name is invalid (max 15 chars)")
    sources = raw.get("sources", [])
    if not isinstance(sources, list) or len(sources) > 32:
        raise GreError("NAT sources must be a list of at most 32 IPv4 subnets")
    sources = [network(x, "Allowed NAT source") for x in sources]
    if len(set(sources)) != len(sources):
        raise GreError("Duplicate NAT source network")
    if enabled and (not wan or not sources):
        raise GreError("Enable NAT only with a WAN interface and allowed source subnet(s)")
    if enabled and "0.0.0.0/0" in sources:
        raise GreError("NAT source 0.0.0.0/0 is too broad; specify client networks")
    return {"enabled": enabled, "wan": wan, "sources": sources}


def make_route(dest, via="", metric="100", table="main", local="", remote=""):
    dest = network(dest, "Route destination")
    if dest == "0.0.0.0/0":
        raise GreError("Default route through GRE is blocked for SSH safety")
    net = ipaddress.ip_network(dest)
    for endpoint in (local, remote):
        if endpoint and ipaddress.ip_address(endpoint) in net:
            raise GreError("Route includes GRE underlay endpoint: tunnel could loop")
    ssh = os.environ.get("SSH_CONNECTION", "").split()
    if ssh:
        try:
            if ipaddress.ip_address(ssh[0]) in net:
                raise GreError("Route includes your SSH client IP and may drop this session")
        except ValueError:
            pass
    via = ip4(via, "Route gateway") if str(via).strip() else ""
    try:
        metric = int(str(metric).strip())
    except ValueError:
        raise GreError("Metric must be an integer")
    if not (0 <= metric <= 4294967295):
        raise GreError("Metric outside allowed range")
    return {"dest": dest, "via": via, "metric": metric,
            "table": table_id(table)}


def make_rule(src, table, priority):
    src = network(src, "Rule source")
    table = table_id(table)
    if table == "main":
        raise GreError("Policy rule should use a dedicated numeric routing table")
    try:
        priority = int(str(priority).strip())
    except ValueError:
        raise GreError("Rule priority must be numeric")
    if not (1000 <= priority <= 32000):
        raise GreError("Rule priority must be 1000..32000")
    return {"src": src, "table": table, "priority": priority}


def validate(c):
    name = str(c.get("name", ""))
    if not NAME_RE.fullmatch(name):
        raise GreError("Tunnel name: 1..15 chars, starts with letter; a-z 0-9 _ . -")
    local = ip4(c.get("local", ""), "Local underlay IP")
    remote = ip4(c.get("remote", ""), "Remote underlay IP")
    if local == remote:
        raise GreError("Local and remote underlay endpoints must differ")
    try:
        iface = ipaddress.IPv4Interface(str(c.get("address", "")).strip())
    except ValueError as e:
        raise GreError(f"GRE inner IPv4 address/prefix: {e}")
    if iface.ip.is_multicast or iface.ip.is_unspecified or iface.ip.is_loopback:
        raise GreError("Inner GRE IP is invalid")
    try:
        mtu, ttl = int(c.get("mtu", 1476)), int(c.get("ttl", 64))
    except (TypeError, ValueError):
        raise GreError("MTU and TTL must be integers")
    if not (576 <= mtu <= 9000):
        raise GreError("MTU must be 576..9000")
    if not (1 <= ttl <= 255):
        raise GreError("TTL must be 1..255")
    key = str(c.get("key", "")).strip()
    if key:
        if not key.isdecimal() or not (0 <= int(key) <= 4294967295):
            raise GreError("GRE key must be 0..4294967295 (not encryption)")
        key = str(int(key))
    extras = c.get("extra_addresses", [])
    if not isinstance(extras, list) or len(extras) > 16:
        raise GreError("extra_addresses must be a list of up to 16 IPv4 prefixes")
    try:
        extras = [str(ipaddress.IPv4Interface(str(a).strip())) for a in extras]
    except ValueError as e:
        raise GreError(f"Invalid additional GRE IPv4 address: {e}") from e
    if len(set(extras + [str(iface)])) != len(extras) + 1:
        raise GreError("Duplicate GRE IPv4 address")
    fw_mode = str(c.get("firewall_mode", "legacy")).strip()
    if fw_mode not in ("legacy", "isolated", "isolated-pass"):
        raise GreError("firewall_mode must be legacy, isolated or isolated-pass")
    routes = [make_route(**dict(r, local=local, remote=remote))
              for r in c.get("routes", [])]
    route_keys = [(r["dest"], r["table"], r["metric"]) for r in routes]
    if len(route_keys) != len(set(route_keys)):
        raise GreError("Duplicate destination/table/metric routes")
    rules = [make_rule(r["src"], r["table"], r["priority"])
             for r in c.get("rules", [])]
    priorities = [r["priority"] for r in rules]
    if len(priorities) != len(set(priorities)):
        raise GreError("Policy rule priorities must be unique")
    internet = normalize_internet(c.get("internet"))
    if internet["enabled"] and internet["wan"] == name:
        raise GreError("NAT WAN interface must not be the GRE interface")
    return {"name": name, "local": local, "remote": remote,
            "address": str(iface), "extra_addresses": extras,
            "firewall_mode": fw_mode, "mtu": mtu, "ttl": ttl,
            "key": key, "routes": routes, "rules": rules,
            "internet": internet}


def config_path(name):
    if not NAME_RE.fullmatch(name):
        raise GreError("Invalid tunnel name")
    return BASE / (name + ".json")


def load(name):
    path = config_path(name)
    if not path.exists():
        raise GreError(f"Not managed by GRE Manager: {name}")
    with path.open(encoding="utf-8") as f:
        raw = json.load(f)
    c = validate(raw)
    if c["name"] != name:
        raise GreError("Config name does not match filename")
    return c


def save(c):
    c = validate(c)
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = config_path(c["name"])
    fd, tmp = tempfile.mkstemp(prefix=".gre-", dir=str(BASE))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(c, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def names():
    if not BASE.exists():
        return []
    return sorted(p.stem for p in BASE.glob("*.json") if NAME_RE.fullmatch(p.stem))


def unit(name):
    config_path(name)
    return f"gre-manager@{name}.service"


def live_interface(name):
    return run(["ip", "link", "show", "dev", name], check=False).returncode == 0


def active(name):
    return run(["systemctl", "is-active", "--quiet", unit(name)], check=False).returncode == 0


def enabled(name):
    return run(["systemctl", "is-enabled", "--quiet", unit(name)], check=False).returncode == 0


def ensure_local_ip(local):
    data = json.loads(run(["ip", "-j", "-4", "addr", "show"]).stdout)
    if not any(a.get("local") == local for link in data
               for a in link.get("addr_info", [])):
        raise GreError(f"Local GRE endpoint {local} is not assigned on any interface")


def outbound_ipv4(target="1.1.1.1"):
    """Find the IPv4 actually used as source for a routed packet, without sending it.

    With a remote IPv4 supplied, this respects that remote's route/policy.
    Never use an internet echo service as the source for `ip tunnel ... local`:
    a NAT public address might not be assigned to this Linux host.
    """
    p = run(["ip", "-j", "-4", "route", "get", target], check=False)
    if p.returncode:
        return ""
    try:
        rows = json.loads(p.stdout)
        if not rows:
            return ""
        value = rows[0].get("src") or rows[0].get("prefsrc") or ""
        return ip4(value, "Outbound source") if value else ""
    except (ValueError, TypeError, KeyError, GreError, json.JSONDecodeError):
        return ""


def observed_public_ipv4():
    """Optional HTTPS observation; not necessarily assignable as a GRE local IP.

    Failure (offline server, filtering, proxy, DNS, TLS) is non-fatal.
    """
    try:
        request = urllib.request.Request(
            "https://api.ipify.org", headers={"User-Agent": "gre-manager/1.4"})
        with urllib.request.urlopen(request, timeout=2) as response:
            value = response.read(100).decode("ascii", errors="strict").strip()
        return ip4(value, "Public IPv4")
    except Exception:
        return ""


def local_ip_preview():
    """Explain why a NAT public IPv4 is not automatically put in GRE local."""
    source = outbound_ipv4()
    seen = observed_public_ipv4()
    if source and seen and source != seen:
        return (source, f"Local route source: {source}; public seen: {seen} (NAT/proxy). "
                "For GRE local use an IP assigned on this server.")
    if source:
        return source, f"Auto-detected outbound source: {source}"
    if seen:
        return "", f"Public seen: {seen}. No assigned outbound IP detected; enter local IP."
    return "", "Outbound IP not detected; enter an IPv4 assigned on this host."


def runtime_path(name):
    config_path(name)
    return STATE / (name + ".json")


def runtime_write(c, nat_rules=None):
    """Keep an ownership token and exact policy rules applied at service start."""
    p = run(["ip", "-j", "link", "show", "dev", c["name"]])
    info = json.loads(p.stdout)[0]
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = runtime_path(c["name"])
    fd, tmp = tempfile.mkstemp(prefix=".state-", dir=str(STATE))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"ifindex": info["ifindex"], "rules": c["rules"],
                       "nat_rules": nat_rules or []}, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def runtime_read(name):
    path = runtime_path(name)
    if not path.exists():
        raise GreError(f"Missing GRE ownership state for {name}; refusing unsafe delete")
    return json.loads(path.read_text(encoding="utf-8"))


def current_rule_priorities():
    data = json.loads(run(["ip", "-j", "-4", "rule", "list"]).stdout)
    return {int(row.get("priority", -1)) for row in data}


def iptables_spec(table, chain, spec, action):
    return ["iptables", "-w", "-t", table, action, chain] + spec


def firewall_chain(name):
    """Dedicated per-tunnel chain. Stable and within iptables chain length."""
    config_path(name)
    return "GMF_" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]


def isolated_firewall_rules(c):
    """Owned per-GRE FORWARD chain: explicit allow and terminal DROP.

    Filter hooks precede the old generic gre+ ACCEPT at installation. This
    prevents traffic traversing that old permissive rule provided nothing
    subsequently inserts a preceding ACCEPT (audit reports such reorderings).
    """
    gre, table = c["name"], "filter"
    chain = firewall_chain(gre)
    label = f"gre-manager:{gre}"
    rules = [{"kind": "chain", "table": table, "chain": chain}]
    internet = c["internet"]
    verdict = "RETURN" if c["firewall_mode"] == "isolated-pass" else "ACCEPT"
    if internet["enabled"]:
        wan = internet["wan"]
        for source in internet["sources"]:
            rules.append({"table": table, "chain": chain, "spec": [
                "-i", gre, "-o", wan, "-s", source,
                "-m", "comment", "--comment", label + ":out", "-j", verdict]})
            rules.append({"table": table, "chain": chain, "spec": [
                "-i", wan, "-o", gre, "-d", source,
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                "-m", "comment", "--comment", label + ":return", "-j", verdict]})
    rules.append({"table": table, "chain": chain, "spec": [
        "-m", "comment", "--comment", label + ":deny", "-j", "DROP"]})
    for direction in ("-i", "-o"):
        rules.append({"table": "filter", "chain": "FORWARD", "spec": [
            direction, gre, "-m", "comment", "--comment", label + ":isolate", "-j", chain],
            "insert": True})
    if internet["enabled"]:
        for source in internet["sources"]:
            rules.append({"table": "nat", "chain": "POSTROUTING", "spec": [
                "-s", source, "-o", internet["wan"],
                "-m", "comment", "--comment", label + ":nat", "-j", "MASQUERADE"]})
    return rules


def internet_firewall_rules(c):
    """Firewall rules used exclusively for this tunnel; exact specs are state-tracked."""
    if c.get("firewall_mode", "legacy") in ("isolated", "isolated-pass"):
        return isolated_firewall_rules(c)
    internet = c["internet"]
    if not internet["enabled"]:
        return []
    wan, gre = internet["wan"], c["name"]
    rules = []
    for source in internet["sources"]:
        label = f"gre-manager:{gre}"
        rules.append({"table": "filter", "chain": "FORWARD", "spec": [
            "-i", gre, "-o", wan, "-s", source, "-m", "comment", "--comment",
            label + ":out", "-j", "ACCEPT"]})
        rules.append({"table": "filter", "chain": "FORWARD", "spec": [
            "-i", wan, "-o", gre, "-d", source, "-m", "conntrack", "--ctstate",
            "ESTABLISHED,RELATED", "-m", "comment", "--comment",
            label + ":return", "-j", "ACCEPT"]})
        rules.append({"table": "nat", "chain": "POSTROUTING", "spec": [
            "-s", source, "-o", wan, "-m", "comment", "--comment",
            label + ":nat", "-j", "MASQUERADE"]})
    return rules


def prepare_internet(c):
    internet = c["internet"]
    if not internet["enabled"]:
        return
    if not shutil.which("iptables"):
        raise GreError("iptables not installed; apt install iptables")
    if not live_interface(internet["wan"]):
        raise GreError(f"WAN interface {internet['wan']} does not exist")
    # Avoid clobbering a sysctl file written by another program/administrator.
    desired = "# Managed by GRE Manager. Do not edit when NAT profiles are enabled.\nnet.ipv4.ip_forward=1\n"
    if FORWARD_SYSCTL.exists() and FORWARD_SYSCTL.read_text() != desired:
        raise GreError(f"Unexpected sysctl file already exists: {FORWARD_SYSCTL}")
    if not FORWARD_SYSCTL.exists():
        FORWARD_SYSCTL.write_text(desired, encoding="utf-8")
        os.chmod(FORWARD_SYSCTL, 0o644)
    if run(["sysctl", "-n", "net.ipv4.ip_forward"]).stdout.strip() != "1":
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])


def _chain_current_rules(table, chain):
    p = run(["iptables", "-w", "-t", table, "-S", chain], check=False)
    if p.returncode:
        return None
    found = []
    for line in p.stdout.splitlines():
        if not line.strip():
            continue
        tokens = shlex.split(line)
        if tokens[:2] == ["-N", chain]:
            continue
        if tokens[:2] != ["-A", chain]:
            raise GreError(f"Unknown iptables content in owned chain {chain}: {line}")
        found.append(tokens[2:])
    return found


def install_internet(c):
    """Idempotent across iptables-restore; adopt only exact expected owned rules.

    A persisted rule is safely reusable when its entire specification matches.
    Unknown content in a supposedly owned chain is never flushed or replaced.
    """
    rules = internet_firewall_rules(c)
    if not rules:
        return []
    if c.get("firewall_mode", "legacy") in ("isolated", "isolated-pass"):
        return install_isolated(c, rules)
    added = []
    try:
        for rule in rules:
            table, chain, spec = rule["table"], rule["chain"], rule["spec"]
            exists = run(iptables_spec(table, chain, spec, "-C"), check=False)
            if exists.returncode == 0:
                continue  # restored by netfilter-persistent: take ownership
            run(["iptables", "-w", "-t", table, "-I", chain, "1"] + spec)
            added.append(rule)
    except Exception:
        remove_internet(added)
        raise
    return rules


def install_isolated(c, rules=None):
    rules = rules if rules is not None else isolated_firewall_rules(c)
    owner = rules[0]
    chain = owner["chain"]
    expected = [r["spec"] for r in rules if r.get("chain") == chain and "spec" in r]
    actual = _chain_current_rules("filter", chain)
    if actual is not None and actual != expected:
        raise GreError(f"Existing {chain} is not identical to manager's expected rules; "
                       "check netfilter-persistent and legacy firewall; refusing takeover")
    added = []
    try:
        if actual is None:
            run(["iptables", "-w", "-t", "filter", "-N", chain])
            added.append(owner)
            for rule in rules:
                if rule.get("chain") == chain and "spec" in rule:
                    run(["iptables", "-w", "-t", "filter", "-A", chain] + rule["spec"])
                    added.append(rule)
        for rule in rules:
            if rule.get("chain") == chain or rule.get("kind") == "chain":
                continue
            table, target, spec = rule["table"], rule["chain"], rule["spec"]
            if run(iptables_spec(table, target, spec, "-C"), check=False).returncode == 0:
                continue
            cmd = "-I" if rule.get("insert") else "-A"
            params = ["1"] if rule.get("insert") else []
            run(["iptables", "-w", "-t", table, cmd, target] + params + spec)
            added.append(rule)
    except Exception:
        remove_internet(added)
        raise
    return rules


def remove_internet(rules):
    """Delete only exact owned rules; never flush built-in/foreign chains."""
    for rule in reversed(rules):
        if rule.get("kind") == "chain":
            # This fails safely if another owner has added rules to our chain.
            run(["iptables", "-w", "-t", rule["table"], "-X", rule["chain"]], check=False)
        else:
            run(iptables_spec(rule["table"], rule["chain"], rule["spec"], "-D"), check=False)


def missing_client_routes(c):
    """Networks behind client must be routed to its GRE interface, unless directly linked."""
    link = ipaddress.IPv4Interface(c["address"]).network
    destinations = [ipaddress.IPv4Network(r["dest"]) for r in c["routes"]
                    if r["table"] == "main"]
    return [src for src in c["internet"]["sources"]
            if not ipaddress.IPv4Network(src).subnet_of(link) and
            not any(ipaddress.IPv4Network(src).subnet_of(r) for r in destinations)]


def up(name):
    c = load(name)
    if live_interface(name):
        raise GreError(f"Interface {name} already exists: refusing to overwrite it")
    ensure_local_ip(c["local"])
    existing = current_rule_priorities()
    for r in c["rules"]:
        if r["priority"] in existing:
            raise GreError(f"IP rule priority {r['priority']} already in use")
    cmd = ["ip", "tunnel", "add", name, "mode", "gre",
           "local", c["local"], "remote", c["remote"], "ttl", str(c["ttl"])]
    if c["key"]:
        cmd += ["key", c["key"]]
    installed_rules = []
    installed_nat = []
    created = False
    try:
        # Isolated mode installs DENY guard BEFORE the GRE device can forward.
        # Legacy profiles keep their original startup sequencing.
        if c["firewall_mode"] in ("isolated", "isolated-pass"):
            if c["internet"]["enabled"]:
                prepare_internet(c)
            installed_nat = install_internet(c)
        run(cmd)
        created = True
        run(["ip", "link", "set", "dev", name, "mtu", str(c["mtu"]), "up"])
        run(["ip", "-4", "addr", "add", c["address"], "dev", name])
        for extra in c.get("extra_addresses", []):
            run(["ip", "-4", "addr", "add", extra, "dev", name])
        for r in c["routes"]:
            args = ["ip", "-4", "route", "add", r["dest"]]
            if r["via"]:
                args += ["via", r["via"]]
            args += ["dev", name, "metric", str(r["metric"]),
                     "table", r["table"]]
            run(args)
        for r in c["rules"]:
            args = ["ip", "-4", "rule", "add", "pref", str(r["priority"]),
                    "from", r["src"], "table", r["table"]]
            run(args)
            installed_rules.append(r)
        if c["firewall_mode"] == "legacy" and c["internet"]["enabled"]:
            prepare_internet(c)
            installed_nat = install_internet(c)
        runtime_write(c, installed_nat)
    except Exception:
        for r in reversed(installed_rules):
            remove_rule(r)
        if created:
            run(["ip", "link", "delete", "dev", name], check=False)
        remove_internet(installed_nat)
        raise


def remove_rule(r):
    run(["ip", "-4", "rule", "del", "pref", str(r["priority"]),
         "from", r["src"], "table", r["table"]], check=False)


def down(name):
    # Use the configuration actually applied, NOT pending edits on disk.
    state = runtime_read(name)
    if live_interface(name):
        info = json.loads(run(["ip", "-j", "link", "show", "dev", name]).stdout)[0]
        if info["ifindex"] != state["ifindex"]:
            raise GreError("GRE interface has changed owner (ifindex mismatch)")
    # Tear down data plane first. Never expose a still-live GRE to inherited
    # gre+ ACCEPT rules after lifting manager isolation hooks.
    if live_interface(name):
        run(["ip", "link", "delete", "dev", name])
    for r in state.get("rules", []):
        remove_rule(r)
    remove_internet(state.get("nat_rules", []))
    rp = runtime_path(name)
    if rp.exists():
        rp.unlink()


def setup():
    if not Path(BIN_PATH).exists():
        raise GreError(f"First install the script at {BIN_PATH}")
    if UNIT_PATH.exists():
        if UNIT_PATH.read_text(encoding="utf-8") != SERVICE:
            raise GreError(f"Existing systemd unit differs: {UNIT_PATH}; not overwriting")
    else:
        UNIT_PATH.write_text(SERVICE, encoding="utf-8")
        os.chmod(UNIT_PATH, 0o644)
    if ACL_UNIT.exists():
        if ACL_UNIT.read_text(encoding="utf-8") != ACL_SERVICE:
            raise GreError(f"Existing input ACL unit differs: {ACL_UNIT}; refusing overwrite")
    else:
        ACL_UNIT.write_text(ACL_SERVICE, encoding="utf-8")
        os.chmod(ACL_UNIT, 0o644)
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    run(["systemctl", "daemon-reload"])


def timestamp():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def backup_all(destination):
    """Root-only, non-overwriting ZIP backup of ALL managed profiles and boot flags.

    The backup is created atomically and never invokes an external tar or shell.
    GRE tunnels configured outside this program are intentionally excluded.
    """
    destination = Path(destination).expanduser()
    if not destination.parent.is_dir():
        raise GreError(f"Backup directory does not exist: {destination.parent}")
    if destination.exists() or destination.is_symlink():
        raise GreError(f"Backup already exists (refusing overwrite): {destination}")
    profiles = []
    for name in names():
        cfg = load(name)   # reject malformed configs rather than silently omitting
        profiles.append((name, cfg, bool(enabled(name)), bool(active(name))))
    manifest = {
        "format": BACKUP_MAGIC, "schema": BACKUP_SCHEMA,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "created_by": f"GRE Manager {VERSION}",
        "note": "Only GRE Manager profiles; runtime interfaces are not captured.",
        "tunnels": [],
        "pool": read_pool(),
    }
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=6) as z:
        for name, cfg, onboot, running in profiles:
            data = _json_bytes(cfg)
            entry = f"profiles/{name}.json"
            manifest["tunnels"].append({
                "name": name, "file": entry,
                "sha256": hashlib.sha256(data).hexdigest(),
                "enabled": onboot, "active_at_backup": running,
            })
            z.writestr(entry, data)
        z.writestr("manifest.json", _json_bytes(manifest))
    fd, temp_path = tempfile.mkstemp(prefix=".gre-backup-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(archive.getvalue())
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp_path, 0o600)
        # link() is atomic and fails if the name already exists: no clobber.
        os.link(temp_path, destination)
    finally:
        if os.path.lexists(temp_path):
            os.unlink(temp_path)
    return {"path": str(destination), "count": len(profiles)}


def safety_backup(prefix):
    BACKUP_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(BACKUP_DIR, 0o700)
    target = BACKUP_DIR / f"{prefix}-{timestamp()}.zip"
    return backup_all(target)["path"]


def read_backup(source):
    """Strict, bounded archive read. Never extracts arbitrary paths to disk."""
    source = Path(source).expanduser()
    if not source.is_file():
        raise GreError(f"Backup not found: {source}")
    if source.stat().st_size > 12 * 1024 * 1024:
        raise GreError("Backup archive exceeds 12 MiB size limit")
    try:
        with zipfile.ZipFile(source, "r") as z:
            members = z.infolist()
            if len(members) > 257:
                raise GreError("Too many entries in archive")
            filenames = [x.filename for x in members]
            if len(filenames) != len(set(filenames)):
                raise GreError("Duplicate ZIP entries")
            if "manifest.json" not in filenames:
                raise GreError("Missing manifest.json")
            for entry in members:
                if entry.is_dir() or entry.file_size > 256 * 1024:
                    raise GreError("Invalid/oversized archive member")
            manifest = json.loads(z.read("manifest.json").decode("utf-8"))
            if not isinstance(manifest, dict) or (manifest.get("format") != BACKUP_MAGIC
                    or manifest.get("schema") != BACKUP_SCHEMA):
                raise GreError("Unsupported GRE Manager backup format/version")
            items = manifest.get("tunnels")
            if not isinstance(items, list) or len(items) > 256:
                raise GreError("Invalid backup tunnel list")
            profiles = {}
            boot = {}
            expected_entries = {"manifest.json"}
            for item in items:
                if not isinstance(item, dict):
                    raise GreError("Invalid tunnel descriptor in backup")
                name = item.get("name")
                if not isinstance(name, str) or not NAME_RE.fullmatch(name):
                    raise GreError("Invalid tunnel name in backup")
                if name in profiles:
                    raise GreError("Duplicate tunnel name in backup")
                entry = f"profiles/{name}.json"
                if item.get("file") != entry or entry not in filenames:
                    raise GreError(f"Missing/unsafe ZIP path for {name}")
                expected_entries.add(entry)
                data = z.read(entry)
                if hashlib.sha256(data).hexdigest() != item.get("sha256"):
                    raise GreError(f"Backup checksum mismatch: {name}")
                cfg = validate(json.loads(data.decode("utf-8")))
                if cfg["name"] != name:
                    raise GreError(f"Profile name mismatch in backup: {name}")
                if type(item.get("enabled")) is not bool:
                    raise GreError(f"Invalid autostart flag for {name}")
                profiles[name] = cfg
                boot[name] = item["enabled"]
            if set(filenames) != expected_entries:
                raise GreError("Archive contains unexpected files")
            # v1.2 backups lack a pool setting; both forms are supported.
            if "pool" in manifest:
                pool_validate(manifest["pool"])
            return profiles, boot, manifest
    except (zipfile.BadZipFile, zipfile.LargeZipFile, UnicodeDecodeError,
            KeyError, TypeError, ValueError) as e:
        raise GreError(f"Invalid backup archive: {e}") from e


def restore_plan(source, local="", replace=False, wan=""):
    profiles, boot, _ = read_backup(source)
    if local:
        local = ip4(local, "Target server local GRE IP")
        profiles = {name: validate(dict(cfg, local=local))
                    for name, cfg in profiles.items()}
    if wan:
        if not IFNAME_RE.fullmatch(wan):
            raise GreError("Target WAN interface has an invalid name")
        profiles = {name: validate(dict(cfg, internet=dict(cfg["internet"], wan=wan)))
                    if cfg["internet"]["enabled"] else cfg
                    for name, cfg in profiles.items()}
    exists = set(names())
    conflicts = sorted(set(profiles) & exists)
    if conflicts and not replace:
        raise GreError("Profiles already exist; restoration stopped: " + ", ".join(conflicts)
                       + ". Use --replace only if you intend to overwrite them.")
    for name in profiles:
        if name not in exists and live_interface(name):
            raise GreError(f"Kernel interface {name} already exists outside GRE Manager")
    return profiles, boot, conflicts


def restore_all(source, local="", replace=False, enable_saved=False, wan=""):
    """Restore config files without starting/restarting tunnels.

    Roll back config and unit enable/disable changes on failure, with best effort.
    """
    if not UNIT_PATH.exists():
        raise GreError("First run: sudo gre-manager init")
    profiles, boot, conflicts = restore_plan(source, local, replace, wan=wan)
    if enable_saved:
        for name, cfg in profiles.items():
            if boot[name]:
                ensure_local_ip(cfg["local"])
    safety = safety_backup("before-restore")
    previous = {name: load(name) for name in conflicts}
    boot_before = {name: enabled(name) for name in profiles}
    changed_boot = []
    try:
        for cfg in profiles.values():
            save(cfg)
        if enable_saved:
            for name in profiles:
                if boot[name] != boot_before[name]:
                    run(["systemctl", "enable" if boot[name] else "disable", unit(name)])
                    changed_boot.append(name)
    except Exception as exc:
        issues = []
        for name in profiles:
            try:
                if name in previous:
                    save(previous[name])
                elif config_path(name).exists():
                    config_path(name).unlink()
            except Exception as rollback_error:
                issues.append(f"profile {name}: {rollback_error}")
        for name in changed_boot:
            try:
                run(["systemctl", "enable" if boot_before[name] else "disable", unit(name)])
            except Exception as rollback_error:
                issues.append(f"autostart {name}: {rollback_error}")
        raise GreError(f"Restore failed: {exc}. Rollback issues: {issues or 'none'}; "
                       f"safety backup: {safety}") from exc
    return {"count": len(profiles), "overwritten": len(conflicts),
            "autostart_restored": enable_saved, "safety_backup": safety,
            "active_untouched": sorted(name for name in profiles if active(name))}


def bulk_plan(new_local, from_local=""):
    """Prepare/validate ALL changes before touching any disk configuration."""
    new_local = ip4(new_local, "New local GRE IP")
    from_local = ip4(from_local, "Old local GRE IP filter") if from_local else ""
    old, updated = {}, {}
    for name in names():
        c = load(name)
        if (not from_local or c["local"] == from_local) and c["local"] != new_local:
            old[name] = c
            updated[name] = validate(dict(c, local=new_local))
    if not updated:
        raise GreError("No managed tunnels matched, or all already use this local IP")
    return old, updated


def bulk_local(new_local, from_local="", apply=False, allow_unassigned=False):
    """Change local address in multiple profiles. Optional controlled live restart.

    All changes are validated and safety-backed-up before writing anything.
    If a restart fails, old disk configs and previous active services are
    restored on a best-effort basis. Network-level atomicity is impossible.
    """
    old, updated = bulk_plan(new_local, from_local)
    if apply and allow_unassigned:
        raise GreError("--apply cannot be combined with --allow-unassigned")
    if not allow_unassigned:
        ensure_local_ip(new_local)
    was_active = [name for name in updated if active(name)]
    safety = safety_backup("before-bulk-local")
    completed = []
    try:
        for cfg in updated.values():
            save(cfg)
        if apply:
            for name in was_active:
                run(["systemctl", "restart", unit(name)])
                completed.append(name)
    except Exception as exc:
        issues = []
        for name, original in old.items():
            try:
                save(original)
            except Exception as rollback_error:
                issues.append(f"profile {name}: {rollback_error}")
        if apply:
            # Restart all originally active profiles: failed one might be stopped.
            for name in was_active:
                try:
                    run(["systemctl", "restart", unit(name)])
                except Exception as rollback_error:
                    issues.append(f"service {name}: {rollback_error}")
        raise GreError(f"Bulk local change failed: {exc}. Rollback issues: "
                       f"{issues or 'none'}; safety backup: {safety}") from exc
    return {"count": len(updated), "changed": sorted(updated),
            "restarted": completed, "pending": sorted(set(updated) - set(completed)),
            "safety_backup": safety}



def live_gre_inventory():
    """Read GRE links via iproute2 JSON. No kernel modifications."""
    response = run(["ip", "-d", "-j", "link", "show"], check=False)
    if response.returncode:
        raise GreError("Cannot inventory kernel GRE devices: " + response.stderr.strip())
    try:
        rows = json.loads(response.stdout)
        if not isinstance(rows, list):
            raise ValueError("not an array")
    except (ValueError, TypeError) as e:
        raise GreError("Unparseable GRE inventory: " + str(e)) from e
    return {x["ifname"]: x for x in rows
            if isinstance(x, dict) and x.get("linkinfo", {}).get("info_kind") == "gre"
            and x.get("ifname")}


def staged_live_profile(name):
    """Build an inert profile for an unmanaged GRE device; do not adopt it live.

    Existing external script/systemd, ip rules and firewall are deliberately
    untouched. Operator must resolve service ownership before cutover.
    """
    config_path(name)
    if config_path(name).exists():
        raise GreError(f"{name} already has a managed configuration")
    info = live_gre_inventory().get(name)
    if info is None:
        raise GreError(f"Unmanaged Linux GRE interface {name} not found")
    data = info.get("linkinfo", {}).get("info_data", {})
    local, remote = data.get("local", ""), data.get("remote", "")
    if not local or not remote or local in ("any", "0.0.0.0") or remote in ("any", "0.0.0.0"):
        raise GreError("Imported GRE must have explicit local and remote IPv4 endpoints")
    if data.get("ikey") and data.get("okey") and data["ikey"] != data["okey"]:
        raise GreError("Different ingress/egress GRE keys: manual conversion required")
    raw = run(["ip", "-j", "-4", "addr", "show", "dev", name])
    addresses = []
    for dev in json.loads(raw.stdout):
        for entry in dev.get("addr_info", []):
            if entry.get("family") == "inet" and entry.get("local"):
                addresses.append(f"{entry['local']}/{entry['prefixlen']}")
    if not addresses:
        raise GreError(f"{name} has no IPv4 address; specify primary GRE IP manually")
    if len(addresses) > 17:
        raise GreError("GRE interface has too many addresses for one profile")
    route_json = run(["ip", "-j", "-4", "route", "show", "table", "all"])
    routes = []
    primary_networks = [ipaddress.IPv4Interface(a).network for a in addresses]
    for route in json.loads(route_json.stdout):
        if route.get("dev") != name or route.get("dst") in ("default", None):
            continue
        dest = route["dst"]
        if route.get("protocol") == "kernel" or route.get("proto") == "kernel":
            continue
        if any(str(n) == network(dest, "Route") for n in primary_networks):
            continue
        table = route.get("table", "main")
        if table in (254, "254"):
            table = "main"
        if table in ("local", 255, "255"):
            continue
        routes.append(make_route(dest, via=route.get("gateway", ""),
                                 metric=route.get("metric", 100), table=table,
                                 local=local, remote=remote))
    key = data.get("ikey", data.get("key", ""))
    if isinstance(key, str) and key.startswith("0x"):
        key = str(int(key, 16))
    c = validate({"name": name, "local": local, "remote": remote,
                  "address": addresses[0], "extra_addresses": addresses[1:],
                  "mtu": info.get("mtu", 1400), "ttl": data.get("ttl", 250),
                  "key": key, "routes": routes, "rules": [],
                  "internet": {"enabled": False, "wan": "", "sources": []},
                  "firewall_mode": "isolated-pass"})
    return {"profile": c,
            "warnings": ["STAGED ONLY: NO OWNERSHIP TRANSFER; kernel device unchanged",
                         "Old scripts/services/cron/boot automation must be disabled manually",
                         "Policy routing rules cannot be attributed reliably: review ip -4 rule",
                         "Old firewall/NAT and iptables-persistent need separate review",
                         "NAT is OFF and isolated forwarding will DROP until configured",
                         "At cutover stop old owner, verify GRE interface removed, then start gre-manager@NAME"]}


def stage_live(name):
    plan = staged_live_profile(name)
    collisions = address_conflicts(plan["profile"]["address"], exclude_name=name)
    if collisions:
        plan["warnings"].append(f"Live network overlaps require review before cutover: {collisions[:8]}")
    safety_backup("before-staging")
    save(plan["profile"])
    return plan


def firewall_audit():
    """Inspect applied and inherited firewall rules without changing anything."""
    result = {"tunnels": {}, "warnings": [], "legacy_rules": [],
              "persistent_firewall": Path("/etc/iptables/rules.v4").exists()}
    filt = run(["iptables", "-w", "-t", "filter", "-S", "FORWARD"], check=False)
    nat = run(["iptables", "-w", "-t", "nat", "-S", "POSTROUTING"], check=False)
    if filt.returncode or nat.returncode:
        result["warnings"].append("Cannot inspect iptables; check permissions/backend")
        return result
    fw_lines = filt.stdout.splitlines()
    nat_lines = nat.stdout.splitlines()
    for line in fw_lines:
        if ("gre+" in line and "ACCEPT" in line) or ("-j ACCEPT" in line and "-i gre" in line):
            result["legacy_rules"].append(line)
    for line in nat_lines:
        if "MASQUERADE" in line and "gre-manager" not in line:
            result["legacy_rules"].append(line)
    for name in names():
        cfg = load(name)
        expected = internet_firewall_rules(cfg)
        notes = []
        if cfg["firewall_mode"] == "legacy":
            notes.append("Legacy mode: no guaranteed isolation from broad FORWARD rules")
        if active(name):
            if cfg["firewall_mode"] in ("isolated", "isolated-pass"):
                chain = firewall_chain(name)
                for direction in ("-i", "-o"):
                    matches = [i for i, line in enumerate(fw_lines)
                               if f"{direction} {name} " in line and f"-j {chain}" in line]
                    if not matches:
                        notes.append(f"MISSING FORWARD isolation hook {direction} for {name}")
                    elif matches[0] > 2:
                        notes.append(f"Isolation hook {direction} is not near top of FORWARD; review order")
                if _chain_current_rules("filter", chain) is None:
                    notes.append(f"Missing isolation chain {chain}")
            else:
                for entry in expected:
                    if entry.get("table") not in ("filter", "nat"):
                        continue
                    if run(iptables_spec(entry["table"], entry["chain"], entry["spec"], "-C"),
                           check=False).returncode != 0:
                        notes.append("Missing manager firewall rule")
        result["tunnels"][name] = {"active": active(name),
                                   "firewall_mode": cfg["firewall_mode"],
                                   "internet_enabled": cfg["internet"]["enabled"],
                                   "issues": notes}
    if any("-j GRE-FORWARD" in x for x in fw_lines):
        for name in names():
            c=load(name)
            if c["firewall_mode"] == "isolated" and active(name):
                result["tunnels"][name]["issues"].append(
                    "ISOLATED ACCEPT may bypass GRE-FORWARD; choose isolated-pass "
                    "when existing downstream firewall checks must still run")
    if result["legacy_rules"]:
        result["warnings"].append("Broad legacy firewall rules exist; disabling NAT "
                                  "may not block forwarding for legacy-mode tunnels")
    if result["persistent_firewall"]:
        result["warnings"].append("netfilter-persistent detected: avoid persisting "
                                  "runtime manager chains before completing migration")
    return result


def firewall_reconcile(name):
    """Reattach missing rules on a live managed tunnel, no interface restart.

    Refuse if config was edited without applying; do not guess which policy
    the running tunnel is intended to use.
    """
    c = load(name)
    if not active(name) or not live_interface(name):
        raise GreError("Reconcile requires an active managed GRE")
    state = runtime_read(name)
    info = json.loads(run(["ip", "-j", "link", "show", "dev", name]).stdout)[0]
    if info["ifindex"] != state["ifindex"]:
        raise GreError("Interface ownership changed (ifindex mismatch)")
    if state.get("nat_rules", []) != internet_firewall_rules(c):
        raise GreError("Saved firewall differs from running policy; apply/restart first")
    if c["internet"]["enabled"]:
        prepare_internet(c)
    rules = install_internet(c)
    state["nat_rules"] = rules
    runtime_write(c, rules)
    return {"tunnel": name, "reconciled": True, "rules": len(rules)}


def underlay_acl_plan(local, wan):
    """Prepare a LOCAL+WAN-scoped GRE input whitelist for a dedicated address.

    Only valid if ALL kernel GRE interfaces bound to this local IP are managed,
    and existing live kernel devices really belong to active manager services.
    No external/legacy interface may be present on the same underlay IP.
    """
    local = ip4(local, "GRE ACL underlay local address")
    wan = str(wan).strip()
    if not IFNAME_RE.fullmatch(wan):
        raise GreError("Invalid GRE ACL WAN interface")
    ensure_local_ip(local)
    if not live_interface(wan):
        raise GreError("GRE ACL WAN interface is missing")
    configured = [c for c in (load(n) for n in names()) if c["local"] == local]
    if not configured:
        raise GreError("No GRE Manager profiles use this underlay local address")
    unmanaged = []
    for name, link in live_gre_inventory().items():
        data = link.get("linkinfo", {}).get("info_data", {})
        if data.get("local") != local:
            continue
        if name not in names() or not active(name):
            unmanaged.append(name)
        else:
            # An active unit alone is insufficient: the kernel interface could
            # have been deleted/recreated by another owner.
            try:
                owned = runtime_read(name)["ifindex"]
                if owned != link.get("ifindex"):
                    unmanaged.append(name)
            except (GreError, KeyError, OSError, ValueError, TypeError):
                unmanaged.append(name)
    if unmanaged:
        raise GreError("Unsafe to enable GRE input ACL: unmanaged or staged live "
                       f"tunnels share local {local}: {', '.join(sorted(unmanaged))}")
    peers = sorted(set(c["remote"] for c in configured),
                   key=lambda ip: int(ipaddress.IPv4Address(ip)))
    chain = "GMI_" + hashlib.sha256(f"{local}:{wan}".encode()).hexdigest()[:12]
    label = f"gre-manager:input:{chain}"
    rules = [{"kind": "chain", "table": "filter", "chain": chain}]
    for peer in peers:
        rules.append({"table":"filter", "chain":chain,
                      "spec":["-s",peer,"-m","comment","--comment",label+":peer","-j","RETURN"]})
    rules.append({"table":"filter", "chain":chain,
                  "spec":["-m","comment","--comment",label+":deny","-j","DROP"]})
    rules.append({"table":"filter", "chain":"INPUT", "insert":True,
                  "spec":["-i",wan,"-d",local,"-p","47","-m","comment",
                          "--comment",label+":hook","-j",chain]})
    return {"local":local,"wan":wan,"peers":peers,"rules":rules,
            "warning":"RETURN for allowed IPs continues existing INPUT filtering. "
                      "Other GRE sources to this local/WAN will be dropped. GRE is not encrypted."}


def underlay_acl_install(plan):
    rules = plan["rules"]
    chain = rules[0]["chain"]
    expected = [r["spec"] for r in rules if r.get("chain") == chain and "spec" in r]
    present = _chain_current_rules("filter",chain)
    if present is not None and present != expected:
        raise GreError(f"Existing ACL chain {chain} differs; manual review required")
    added=[]
    try:
        if present is None:
            run(["iptables","-w","-t","filter","-N",chain])
            added.append(rules[0])
            for rule in rules[1:-1]:
                run(["iptables","-w","-t","filter","-A",chain]+rule["spec"])
                added.append(rule)
        hook=rules[-1]
        if run(iptables_spec("filter","INPUT",hook["spec"],"-C"),check=False).returncode:
            run(["iptables","-w","-t","filter","-I","INPUT","1"]+hook["spec"])
            added.append(hook)
    except Exception:
        remove_internet(added)
        raise
    return rules


def underlay_acl_restore():
    if not ACL_PATH.exists():
        raise GreError("Input ACL not configured")
    raw=json.loads(ACL_PATH.read_text(encoding="utf-8"))
    plan=underlay_acl_plan(raw["local"],raw["wan"])
    rules=underlay_acl_install(plan)
    STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    ACL_RUNTIME.write_text(json.dumps(rules),encoding="utf-8")
    os.chmod(ACL_RUNTIME,0o600)
    return plan


def underlay_acl_clear():
    if not ACL_RUNTIME.exists():
        raise GreError("No GRE input ACL ownership state; refusing unsafe cleanup")
    rules=json.loads(ACL_RUNTIME.read_text(encoding="utf-8"))
    remove_internet(rules)
    ACL_RUNTIME.unlink()


def underlay_acl_reconcile():
    """Recover missing INPUT hook or update peers while DROP stays in force.

    Never blindly replace an ACL chain owned by a different process.
    """
    if not ACL_PATH.exists():
        raise GreError("GRE INPUT ACL is not configured")
    settings=json.loads(ACL_PATH.read_text(encoding="utf-8"))
    plan=underlay_acl_plan(settings["local"],settings["wan"])
    rules=plan["rules"]
    chain=rules[0]["chain"]
    current=_chain_current_rules("filter",chain)
    expected=[r["spec"] for r in rules[1:-1]]
    if current is None or current == expected:
        underlay_acl_install(plan)
    else:
        if not ACL_RUNTIME.exists():
            raise GreError("INPUT ACL differs and runtime ownership missing; refusing rewrite")
        old=json.loads(ACL_RUNTIME.read_text(encoding="utf-8"))
        if old[0].get("chain") != chain:
            raise GreError("Unexpected INPUT ACL ownership token")
        former=[r["spec"] for r in old[1:-1]]
        if current != former:
            raise GreError("INPUT ACL chain modified externally; refusing unsafe rewrite")
        hook=old[-1]
        if run(iptables_spec("filter","INPUT",hook["spec"],"-C"),check=False).returncode:
            raise GreError("INPUT GRE hook missing; reconcile hook before modifying peer list")
        lock=["-m","comment","--comment",f"gre-manager:acl:{chain}:maintenance","-j","DROP"]
        run(["iptables","-w","-t","filter","-I",chain,"1"]+lock)
        removed=[]
        added=[]
        try:
            for entry in old[1:-2]:
                run(iptables_spec("filter",chain,entry["spec"],"-D"))
                removed.append(entry)
            for entry in reversed(rules[1:-2]):
                run(["iptables","-w","-t","filter","-I",chain,"2"]+entry["spec"])
                added.append(entry)
        except Exception as exc:
            problems=[]
            for entry in added:
                try: run(iptables_spec("filter",chain,entry["spec"],"-D"))
                except Exception as x: problems.append(str(x))
            for entry in reversed(removed):
                try: run(["iptables","-w","-t","filter","-I",chain,"2"]+entry["spec"])
                except Exception as x: problems.append(str(x))
            if not problems:
                run(iptables_spec("filter",chain,lock,"-D"))
            raise GreError(f"GRE INPUT ACL peer update failed: {exc}. "
                           f"Rollback: {problems or 'OK'} (DROP kept if rollback failed)") from exc
        run(iptables_spec("filter",chain,lock,"-D"))
    STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    ACL_RUNTIME.write_text(json.dumps(rules),encoding="utf-8")
    os.chmod(ACL_RUNTIME,0o600)
    return plan


def underlay_acl_enable(local,wan):
    """Explicit opt-in with dedicated service persistence, no firewall flush."""
    if not ACL_UNIT.exists():
        raise GreError("Run 'sudo gre-manager init' to install optional ACL systemd unit")
    plan=underlay_acl_plan(local,wan)
    if ACL_PATH.exists():
        old=json.loads(ACL_PATH.read_text(encoding="utf-8"))
        if old!={"local":plan["local"],"wan":plan["wan"]}:
            raise GreError("Different GRE input ACL already configured; disable old one first")
    ACL_PATH.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    ACL_PATH.write_text(json.dumps({"local":plan["local"],"wan":plan["wan"]})+"\n")
    os.chmod(ACL_PATH,0o600)
    service="gre-manager-input-acl.service"
    was_active=run(["systemctl","is-active","--quiet",service],check=False).returncode==0
    p=run(["systemctl","enable","--now",service],check=False)
    if p.returncode:
        raise GreError("ACL service failed (configuration saved for review): "+p.stderr)
    if was_active:
        underlay_acl_reconcile()
    return plan


def underlay_acl_disable():
    if not ACL_PATH.exists():
        raise GreError("No managed public GRE input ACL is configured")
    run(["systemctl","disable","--now","gre-manager-input-acl.service"])
    ACL_PATH.unlink()


# Dialog UI. Dialog paints to stderr (the TTY) and returns user input via stdout.
def dlg(args):
    return run(["dialog", "--stdout", "--no-shadow",
                "--backtitle", f"GRE Manager v{VERSION} | Debian / Ubuntu"] + args,
               check=False)


def msg(value, title="GRE Manager"):
    dlg(["--title", title, "--msgbox", str(value)[:3600], "16", "95"])


def confirm(value, title="Confirmation"):
    return dlg(["--title", title, "--yesno", value, "12", "94"]).returncode == 0


def menu(title, description, options):
    if not options:
        msg("There are no entries", title)
        return None
    args = ["--title", title, "--menu", description, "23", "100", "16"]
    for k, v in options:
        args += [str(k), str(v)[:70]]
    p = dlg(args)
    return p.stdout.strip() if p.returncode == 0 else None


def form(title, intro, fields):
    h = max(18, len(fields) + 11)
    args = ["--title", title, "--form", intro, str(h), "96",
            str(len(fields) + 2)]
    for i, (label, default) in enumerate(fields, 1):
        args += [str(label) + ":", str(i), "2", str(default),
                 str(i), "29", "58", "58"]
    p = dlg(args)
    if p.returncode != 0:
        return None
    result = p.stdout.split("\n")
    if result and result[-1] == "":
        result.pop()
    while len(result) < len(fields):
        result.append("")
    return [x.strip() for x in result]


def textbox(title, content):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as f:
        f.write(content)
        f.flush()
        dlg(["--title", title, "--textbox", f.name, "25", "105"])


def safe(fn):
    try:
        return fn()
    except Exception as e:
        msg(str(e), "Operation failed")
        return None


def tunnel_fields(c=None):
    c = c or {}
    if c:
        local_guess, note = c["local"], "Local = a server-assigned IPv4; remote = GRE peer IPv4."
    else:
        local_guess, note = local_ip_preview()
        allocation = allocate_pair(read_pool())
        c["address"] = allocation["server"]
        note += f" | Pool {read_pool()} -> client {allocation['peer']}"
    values = form("GRE tunnel parameters", note + "\nGRE key is optional (not encryption).", [
        ("Interface name", c.get("name", "gre1")),
        ("Local underlay IP", local_guess),
        ("Remote underlay IP", c.get("remote", "")),
        ("Server GRE IP / prefix", c.get("address", "10.255.10.1/30")),
        ("MTU", c.get("mtu", 1400)),
        ("TTL", c.get("ttl", 250)),
        ("GRE key (optional)", c.get("key", "")),
        ("Other GRE IPv4 CIDRs (comma)", ",".join(c.get("extra_addresses", []))),
    ])
    if values is None:
        return None
    values = list(values) + [""] * max(0, 8 - len(values))
    name, local, remote, address, mtu, ttl, key, extra_text = values[:8]
    result = validate(dict(name=name, local=local, remote=remote,
                           address=address, mtu=mtu, ttl=ttl, key=key,
                           extra_addresses=[x.strip() for x in extra_text.split(",") if x.strip()],
                           firewall_mode=c.get("firewall_mode", "legacy"),
                           routes=c.get("routes", []), rules=c.get("rules", []),
                           internet=c.get("internet", {})))
    # If the /30 server-side GRE IP changes, follow it with the NAT peer /32.
    # Do not touch explicitly configured client LANs or unrelated source nets.
    if c and result["address"] != c["address"] and c.get("internet", {}).get("sources", []):
        old_peer, new_peer = peer_address(c), peer_address(result)
        old_src = old_peer + "/32" if old_peer else ""
        if old_src in result["internet"]["sources"]:
            if not new_peer:
                raise GreError("GRE prefix changed to non-/30; update the NAT source manually")
            new_src = new_peer + "/32"
            updated_sources = [new_src if x == old_src else x for x in result["internet"]["sources"]]
            result = validate(dict(result, internet=dict(result["internet"], sources=updated_sources)))
    # Multihomed systems may use another WAN for this particular remote.
    # Confirm before changing the local endpoint the user supplied.
    expected = outbound_ipv4(remote)
    if expected and expected != local:
        if confirm(f"Route to peer {remote} currently uses source {expected},\n"
                   f"but the form says local {local}.\n\n"
                   f"Replace local with {expected}? (No = keep your value)",
                   "GRE underlay source mismatch"):
            result["local"] = expected
            result = validate(result)
    return result


def edit_save(old, modified):
    if old["address"] != modified["address"]:
        conflicts = address_conflicts(modified["address"], exclude_name=old["name"])
        if conflicts:
            raise GreError(f"GRE address change conflicts with host network: {conflicts[:8]}")
    for extra in set(modified.get("extra_addresses", [])) - set(old.get("extra_addresses", [])):
        conflicts = address_conflicts(extra, exclude_name=old["name"])
        if conflicts:
            raise GreError(f"Additional GRE IP conflicts with host network: {conflicts[:8]}")
    save(modified)
    name = old["name"]
    if active(name):
        if confirm("Saved to disk. Restart this GRE tunnel now to apply?\n"
                   "Restart interrupts existing traffic over this tunnel!"):
            p = run(["systemctl", "restart", unit(name)], check=False)
            if p.returncode:
                save(old)
                recovery = run(["systemctl", "restart", unit(name)], check=False)
                msg("NEW CONFIG FAILED. Old config restored.\n\n" +
                    (p.stderr or p.stdout)[-2000:] + "\n\nOld config restart: " +
                    ("OK" if recovery.returncode == 0 else "FAILED; check journalctl"),
                    "Rollback")
            else:
                msg("Tunnel restarted with updated configuration")
        else:
            msg("Changes saved; running tunnel unchanged. Apply using Restart.")
    else:
        msg("Saved. Start and enable the tunnel from its menu.")


def auto_internet_config(c, wan="", lan_networks=(), enabled=True):
    """Generate per-link WAN/NAT profile and reverse LAN routes for a NEW GRE.

    We know the /30 peer from the allocation; LAN behind RouterOS must be
    supplied by the operator. No default routes or changes to other interfaces.
    """
    c = validate(c)
    if not enabled:
        return c
    peer = peer_address(c)
    if not peer:
        raise GreError("Automatic NAT needs a /30 GRE link; configure peer/sources manually")
    wan = str(wan).strip() or guess_wan()
    if not wan:
        raise GreError("Internet WAN could not be detected; enter it explicitly")
    sources = [peer + "/32"]
    routes = list(c["routes"])
    for raw in lan_networks:
        raw = str(raw).strip()
        if not raw:
            continue
        subnet = network(raw, "LAN behind MikroTik")
        if subnet == "0.0.0.0/0":
            raise GreError("Client LAN cannot be 0.0.0.0/0")
        if ipaddress.IPv4Network(subnet).overlaps(ipaddress.IPv4Interface(c["address"]).network):
            raise GreError(f"Client LAN {subnet} overlaps its GRE /30 link")
        if subnet in sources:
            raise GreError(f"Duplicate client LAN: {subnet}")
        sources.append(subnet)
        # Connected /30 needs no additional route; LANs behind peer do.
        if not any(r["dest"] == subnet and r["table"] == "main" for r in routes):
            routes.append(make_route(subnet, local=c["local"], remote=c["remote"]))
    return validate(dict(c, routes=routes, internet={
        "enabled": True, "wan": wan, "sources": sources}))


def new_tunnel():
    c = tunnel_fields()
    if c is None:
        return
    path = config_path(c["name"])
    if path.exists() or live_interface(c["name"]):
        raise GreError("This config or interface name already exists")
    new_net = ipaddress.IPv4Interface(c["address"]).network
    for existing_name in names():
        old_net = ipaddress.IPv4Interface(load(existing_name)["address"]).network
        if new_net.overlaps(old_net):
            raise GreError(f"Tunnel GRE subnet {new_net} overlaps {existing_name}: {old_net}")

    # Check the live kernel and legacy peer configs as well as manager profiles.
    collisions = address_conflicts(c["address"])
    if collisions:
        raise GreError("GRE inner address conflicts with host network: " +
                       "; ".join(f"{n} ({why})" for n, why in collisions[:8]))
    peer = peer_address(c)
    suggested_wan = guess_wan()
    values = form("Automatic Internet sharing", 
                  "NAT + forwarding are prepared AUTOMATICALLY for this GRE.\n"
                  "Enter LAN CIDRs behind MikroTik if Internet is needed for its LAN; "
                  "reverse routes will be created automatically.", [
        ("Enable Internet/NAT (yes/no)", "yes"),
        ("Server WAN interface", suggested_wan),
        ("MikroTik LANs CIDR (comma)", ""),
    ])
    if values is None:
        return
    yesno, wan, lan_text = values
    if yesno.lower() not in ("yes", "y", "no", "n"):
        raise GreError("Enable Internet/NAT must be yes or no")
    nat_enabled = yesno.lower() in ("yes", "y")
    c = auto_internet_config(c, wan=wan,
                             lan_networks=[x.strip() for x in lan_text.split(",") if x.strip()],
                             enabled=nat_enabled)
    c = validate(dict(c, firewall_mode="isolated"))
    if nat_enabled:
        for r in c["routes"]:
            if r["table"] == "main":
                for existing_name in names():
                    old = load(existing_name)
                    if any(ipaddress.IPv4Network(r["dest"]).overlaps(ipaddress.IPv4Network(o["dest"]))
                           for o in old["routes"] if o["table"] == "main"):
                        raise GreError(f"Client LAN route {r['dest']} conflicts with a route in {existing_name}; "
                                       "use separate routing tables for overlapping LANs")
    summary = [f"Tunnel: {c['name']}   {c['local']} -> {c['remote']}",
               f"GRE server: {c['address']}",
               f"MikroTik peer: {peer + '/30' if peer else '(configure manually)'}",
               f"Automatic NAT: {'ON' if nat_enabled else 'OFF'}"]
    if nat_enabled:
        summary += [f"WAN: {c['internet']['wan']}",
                    "Allowed sources: " + ", ".join(c["internet"]["sources"]),
                    "Client LAN routes: " + ", ".join(r["dest"] for r in c["routes"])]
    summary += ["", "Rules take effect when the GRE service starts.",
                "Forwarding will be enabled for NAT; it is not reverted automatically."]
    textbox("Review new GRE / Internet settings", "\n".join(summary))
    if not confirm("Save this GRE tunnel and its Internet/NAT configuration?"):
        return
    save(c)
    # Update the existing optional protocol-47 allowlist before bringing up a
    # new peer. If it cannot be refreshed, leave profile saved but STOPPED.
    if ACL_PATH.exists():
        try:
            underlay_acl_reconcile()
        except GreError as error:
            msg(f"Profile saved but not activated: INPUT GRE ACL must be "
                f"reconciled first. {error}", "ACL must be updated")
            return
    if confirm("Start GRE now AND enable autostart on boot?\n"
               "This will activate GRE, forwarding and NAT rules (if enabled).\n"
               "No = keep profile saved but STOPPED.", "Activate new GRE"):
        p = run(["systemctl", "enable", "--now", unit(c["name"])], check=False)
        if p.returncode:
            # `systemctl enable --now` may leave a FAILED unit enabled on boot.
            run(["systemctl", "disable", unit(c["name"])], check=False)
            msg("Config saved, but start failed. Autostart disabled.\n\n" +
                (p.stderr or p.stdout)[-2300:], "GRE start failed")
            return
        msg(f"Created and STARTED {c['name']}.\nServer GRE: {c['address']}\n"
            f"MikroTik GRE: {peer + '/30' if peer else '(set manually)'}\n"
            f"Internet NAT: {'ENABLED' if nat_enabled else 'DISABLED'}")
    else:
        msg(f"Created {c['name']} (stopped). NAT is saved in its profile and "
            "will activate when the tunnel is started.")


def route_text(r):
    return (f"{r['dest']} via {r['via'] or 'dev GRE'}  "
            f"metric {r['metric']} table {r['table']}")


def routes_ui(name):
    while True:
        c = load(name)
        opts = [("+", "Add route")]
        opts += [(str(i), route_text(r)) for i, r in enumerate(c["routes"], 1)]
        choice = menu(f"Routes / {name}", "Select route to remove, or + to add", opts)
        if choice is None:
            return
        if choice == "+":
            v = form("Add route", "'via' empty = directly through GRE. Table: main or number.", [
                ("Destination CIDR", "192.168.20.0/24"),
                ("Via (optional GRE peer IP)", ""),
                ("Metric", "100"),
                ("Routing table", "main"),
            ])
            if v is None:
                continue
            r = make_route(*v, local=c["local"], remote=c["remote"])
            new = copy.deepcopy(c)
            new["routes"].append(r)
            edit_save(c, validate(new))
        else:
            idx = int(choice) - 1
            if confirm("Remove route?\n" + route_text(c["routes"][idx])):
                new = copy.deepcopy(c)
                new["routes"].pop(idx)
                edit_save(c, new)


def rules_ui(name):
    while True:
        c = load(name)
        opts = [("+", "Add policy rule")]
        opts += [(str(i), f"from {r['src']} table {r['table']} pref {r['priority']}")
                 for i, r in enumerate(c["rules"], 1)]
        choice = menu(f"Policy routing / {name}",
                      "Custom routing tables require a matching ip rule.", opts)
        if choice is None:
            return
        if choice == "+":
            v = form("Add source routing rule", "Choose a globally unique priority.", [
                ("Source prefix", "192.168.10.0/24"),
                ("Table numeric ID", "200"),
                ("Priority (1000..32000)", "12000"),
            ])
            if v is None:
                continue
            new = copy.deepcopy(c)
            new["rules"].append(make_rule(*v))
            edit_save(c, validate(new))
        else:
            idx = int(choice) - 1
            if confirm("Remove selected policy rule?"):
                new = copy.deepcopy(c)
                new["rules"].pop(idx)
                edit_save(c, new)


def tunnel_status(name):
    c = load(name)
    chunks = ["GRE Manager v" + VERSION,
              "Config: " + str(config_path(name)),
              "Service active: " + str(active(name)),
              "Autostart enabled: " + str(enabled(name)),
              "", json.dumps(c, indent=2), ""]
    for title, args in [
        ("LIVE LINK + COUNTERS", ["ip", "-s", "-d", "link", "show", "dev", name]),
        ("TUNNEL", ["ip", "-d", "tunnel", "show", name]),
        ("UNDERLAY ROUTE", ["ip", "-4", "route", "get", c["remote"]]),
        ("IPv4 ADDRESSES", ["ip", "-4", "addr", "show", "dev", name]),
        ("ROUTES MAIN", ["ip", "-4", "route", "show", "dev", name, "table", "main"]),
        ("SERVICE", ["systemctl", "status", unit(name), "--no-pager", "--full"]),
        ("LOGS", ["journalctl", "-u", unit(name), "-n", "40", "--no-pager"]),
    ]:
        p = run(args, check=False)
        chunks += ["\n### " + title, p.stdout or p.stderr or "(empty)"]
    for t in set(r["table"] for r in c["routes"] if r["table"] != "main"):
        p = run(["ip", "-4", "route", "show", "table", t], check=False)
        chunks += ["\n### ROUTING TABLE " + t, p.stdout or p.stderr]
    p = run(["ip", "-4", "rule", "show"], check=False)
    chunks += ["\n### POLICY RULES", p.stdout or p.stderr]
    chunks += ["\n### INTERNET NAT SETTINGS", json.dumps(c["internet"], indent=2),
               "Kernel IPv4 forwarding enabled: " + str(forwarding_status())]
    if c["internet"]["enabled"]:
        chunks += ["Missing configured return routes: " +
                   (", ".join(missing_client_routes(c)) or "none")]
        for table, chain in [("filter", "FORWARD"), ("nat", "POSTROUTING")]:
            output = run(["iptables", "-w", "-t", table, "-S", chain], check=False)
            matching = [line for line in (output.stdout or "").splitlines()
                        if f"gre-manager:{name}:" in line]
            chunks += [f"\n### MANAGED IPTABLES {table}/{chain}",
                       "\n".join(matching) or output.stderr or "(none found)"]
    textbox("Tunnel diagnostics: " + name, "\n".join(chunks))


def ping_ui(name):
    c = load(name)
    a = ipaddress.ip_interface(c["address"])
    suggested = ""
    if a.network.num_addresses <= 256:
        others = [str(ip) for ip in a.network.hosts() if ip != a.ip]
        if len(others) == 1:
            suggested = others[0]
    p = dlg(["--title", "Ping inner GRE peer", "--inputbox",
             "IPv4 address reachable through this GRE (usually the other /30 IP):",
             "11", "85", suggested])
    if p.returncode != 0:
        return
    target = ip4(p.stdout.strip(), "Ping destination")
    result = run(["ping", "-n", "-I", name, "-c", "3", "-W", "2", target],
                 check=False)
    textbox(f"Ping {target} via {name}", result.stdout or result.stderr)


def tunnel_ui(name):
    while config_path(name).exists():
        c = load(name)
        desc = (f"{name}: {c['local']} -> {c['remote']} | "
                f"{'ACTIVE' if active(name) else 'STOPPED'} | "
                f"{'BOOT ON' if enabled(name) else 'BOOT OFF'}")
        choice = menu(name, desc, [
            ("1", "Status, routes, systemd logs"),
            ("2", "Edit GRE endpoints / address / MTU / TTL / key"),
            ("3", "Add/remove IPv4 routes (gateway, metric, table)"),
            ("4", "Policy routing rules (source, table, priority)"),
            ("5", "Enable autostart and start"),
            ("6", "Stop and disable autostart"),
            ("7", "Restart / apply saved configuration"),
            ("8", "Delete config and tunnel"),
            ("9", "Ping inner GRE peer"),
            ("10", "Internet via server: NAT / allowed client networks"),
            ("11", "MikroTik configuration / peer address"),
        ])
        if choice is None:
            return
        if choice == "1":
            tunnel_status(name)
        elif choice == "2":
            new = tunnel_fields(c)
            if new is not None:
                if new["name"] != name:
                    raise GreError("Interface cannot be renamed in Edit; create a new one")
                edit_save(c, new)
        elif choice == "3":
            routes_ui(name)
        elif choice == "4":
            rules_ui(name)
        elif choice == "5":
            p = run(["systemctl", "enable", "--now", unit(name)], check=False)
            if p.returncode:
                raise GreError((p.stderr or p.stdout) + "\nSee status/logs for details")
            msg("Autostart enabled; service active. Use Restart to apply pending edits.")
        elif choice == "6":
            if confirm("Stop this tunnel NOW and disable startup?\n"
                       "Traffic traversing it will be interrupted."):
                run(["systemctl", "disable", "--now", unit(name)])
                msg("Tunnel stopped and autostart disabled")
        elif choice == "7":
            if confirm("Restart tunnel and apply configuration NOW?\n"
                       "GRE traffic will briefly disconnect."):
                run(["systemctl", "restart", unit(name)])
                msg("Restart completed")
        elif choice == "9":
            ping_ui(name)
        elif choice == "10":
            internet_ui(name)
        elif choice == "11":
            textbox(f"MikroTik setup: {name}", mikrotik_notes(c))
        elif choice == "8":
            if confirm("PERMANENTLY delete this GRE config?\n"
                       "The tunnel will be stopped and disabled first.",
                       "Delete tunnel"):
                run(["systemctl", "disable", "--now", unit(name)])
                config_path(name).unlink()
                msg("Tunnel config removed")
                return


def host_network_ui():
    src = outbound_ipv4()
    public = observed_public_ipv4()
    lines = ["NETWORK OVERVIEW (read-only)",
             "Outbound source address: " + (src or "not detected"),
             "Public IPv4 observed via HTTPS: " + (public or "unavailable"),
             "WARNING: A public IPv4 seen via HTTPS might be NAT/proxy. "
             "GRE local must exist on an interface of this host.", ""]
    for label, cmd in [
        ("HOST IPv4 ADDRESSES", ["ip", "-br", "-4", "addr", "show"]),
        ("DEFAULT IPv4 ROUTES", ["ip", "-4", "route", "show", "default"]),
        ("MAIN ROUTING TABLE", ["ip", "-4", "route", "show", "table", "main"]),
        ("POLICY RULES", ["ip", "-4", "rule", "show"]),
        ("GRE TUNNELS (including unmanaged)", ["ip", "-d", "tunnel", "show"]),
    ]:
        p = run(cmd, check=False)
        lines.extend(["### " + label, p.stdout or p.stderr or "(empty)", ""])
    textbox("Host network overview", "\n".join(lines))


def unmanaged_ui():
    p = run(["ip", "-d", "tunnel", "show"], check=False)
    textbox("GRE / IP tunnels in Linux (read-only)",
            "All IP tunnels visible to the kernel, including ones not managed "
            "by this utility.\n\n" + (p.stdout or p.stderr or "(empty)"))


def input_prompt(title, prompt, default=""):
    p = dlg(["--title", title, "--inputbox", prompt, "13", "100", str(default)])
    return p.stdout.strip() if p.returncode == 0 else None


def backup_ui():
    target = input_prompt("Backup all managed GRE tunnels",
                          "Save all GRE Manager profiles, routes, rules and autostart "
                          "settings into a root-only ZIP.\nThe destination directory must exist.",
                          f"/root/gre-manager-{timestamp()}.zip")
    if target is None:
        return
    result = backup_all(target)
    msg(f"Backed up {result['count']} managed tunnels.\n"
        f"File: {result['path']}\nPermissions: 0600\n\n"
        "Copy this ZIP securely to the target server.\n"
        "External/unmanaged tunnels are not included.", "Backup completed")


def restore_ui():
    source = input_prompt("Import GRE backup", "Enter the path to a GRE Manager ZIP backup:")
    if source is None:
        return
    profiles, boot, manifest = read_backup(source)
    if not profiles:
        msg("Archive contains zero tunnels. Nothing to restore.")
        return
    suggestion = outbound_ipv4()
    replacement = input_prompt("Target server GRE local IP",
                               "Enter the NEW server-assigned local IP for ALL imported GRE tunnels.\n"
                               "Leave EMPTY to keep per-tunnel local addresses in the backup.\n"
                               "If restoring multiple WAN addresses, leave blank and edit separately.",
                               suggestion)
    if replacement is None:
        return
    # NAT WAN interface is host-specific and can differ on the new server.
    new_wan = ""
    if any(c["internet"]["enabled"] for c in profiles.values()):
        new_wan = input_prompt("Destination server Internet WAN interface",
                               "Optional: replace the NAT egress interface in all imported\n"
                               "profiles with NAT enabled. Leave empty to keep the backup values.",
                               guess_wan())
        if new_wan is None:
            return
    profiles, boot, conflicts = restore_plan(source, replacement, replace=True, wan=new_wan)
    details = [f"BACKUP: {source}",
               f"Created: {manifest.get('created_utc', '?')}",
               f"Profiles: {len(profiles)}; existing profiles to replace: {len(conflicts)}",
               f"Destination NAT WAN override: {new_wan or '(unchanged)'}",
               "Restore writes files; active interfaces are NEVER restarted.",
               "Autostart can be restored optionally; services will NOT start now.", ""]
    for name, cfg in profiles.items():
        details.append(f"{name:15} local={cfg['local']:15} remote={cfg['remote']:15} "
                       f"routes={len(cfg['routes'])} rules={len(cfg['rules'])} "
                       f"autostart={'yes' if boot[name] else 'no'} "
                       f"{'[EXISTS]' if name in conflicts else '[NEW]'}")
    textbox("Restore preview (read-only)", "\n".join(details))
    replace = False
    if conflicts:
        replace = confirm("Existing GRE Manager configs would be OVERWRITTEN:\n" +
                          ", ".join(conflicts) + "\n\n"
                          "Running tunnels remain unchanged until manually restarted.\n"
                          "Continue with overwriting these disk profiles?", "Overwrite profiles?")
        if not replace:
            return
    enable_saved = confirm("Also restore saved autostart ENABLED/DISABLED flags?\n"
                           "This does NOT start or stop any running tunnel.\n\n"
                           "Yes: copy boot policy from archive.\nNo: leave target boot policy unchanged.",
                           "Autostart settings")
    if not confirm("RESTORE these GRE configurations now?\n"
                   "A safety backup of target profiles will be created first.\n"
                   "No active GRE tunnel will be restarted.", "Final restore confirmation"):
        return
    result = restore_all(source, replacement, replace, enable_saved, wan=new_wan)
    msg(f"Restored {result['count']} tunnels; replaced {result['overwritten']}.\n"
        f"Autostart restored: {result['autostart_restored']}\n"
        f"Pre-restore backup: {result['safety_backup']}\n\n"
        "Running interfaces were NOT changed.\n"
        "Review config/peer IP and start or restart tunnels individually.",
        "Restore finished")


def bulk_local_ui():
    found = names()
    if not found:
        msg("No managed GRE tunnels exist yet.")
        return
    newip = input_prompt("Bulk change GRE local address",
                         "NEW local underlay IPv4 assigned to THIS SERVER:\n"
                         "Default is the outbound source IP, not a NAT public IP.",
                         outbound_ipv4())
    if newip is None:
        return
    fromip = input_prompt("Optional old address filter",
                          "ONLY update tunnels whose local IP equals this old address.\n"
                          "Leave empty to update ALL managed tunnels (including multi-WAN).", "")
    if fromip is None:
        return
    old, updated = bulk_plan(newip, fromip)
    lines = [f"NEW local IP: {newip}", f"Filter old IP: {fromip or '(all)'}",
             f"Profiles to change: {len(updated)}", ""]
    for name, cfg in updated.items():
        lines.append(f"{name:15} {old[name]['local']:15} -> {cfg['local']:15} "
                     f"peer={cfg['remote']} "
                     f"{'RUNNING' if active(name) else 'STOPPED'}")
        candidate = outbound_ipv4(cfg["remote"])
        if candidate and candidate != newip:
            lines.append(f"  WARN: route to peer currently selects src {candidate}")
    lines.extend(["", "Config-only change never touches running tunnels.",
                  "An optional restart will interrupt GRE traffic and may drop SSH."])
    textbox("Bulk local IP change preview", "\n".join(lines))
    allow_unassigned = False
    try:
        ensure_local_ip(newip)
    except GreError as e:
        if not confirm(str(e) + "\n\nSave configuration ONLY for future migration?\n"
                       "Active tunnels cannot be restarted with an unassigned IP.",
                       "Address is not assigned"):
            return
        allow_unassigned = True
    apply = False
    if not allow_unassigned and any(active(name) for name in updated):
        apply = confirm("Restart ALL currently active affected GRE tunnels now?\n\n"
                        "YES: immediate network interruptions; could disconnect SSH.\n"
                        "NO: only update saved configs; manually restart later.",
                        "Apply changes immediately?")
    if not confirm(f"Save new local={newip} for {len(updated)} GRE profiles?\n"
                   f"Restart active tunnels now: {'YES' if apply else 'NO'}\n"
                   "A full safety backup will be written first.", "Confirm bulk update"):
        return
    result = bulk_local(newip, fromip, apply, allow_unassigned)
    msg(f"Changed: {result['count']} GRE profiles.\n"
        f"Restarted: {len(result['restarted'])}; pending apply: {len(result['pending'])}.\n"
        f"Pre-change backup: {result['safety_backup']}", "Bulk update finished")



def forwarding_status():
    p = run(["sysctl", "-n", "net.ipv4.ip_forward"], check=False)
    return p.stdout.strip() == "1" if p.returncode == 0 else None


def guess_wan():
    p = run(["ip", "-j", "-4", "route", "get", "1.1.1.1"], check=False)
    if p.returncode == 0:
        try:
            return json.loads(p.stdout)[0].get("dev", "")
        except (IndexError, KeyError, ValueError, TypeError):
            pass
    return ""


def mikrotik_notes(c):
    peer = peer_address(c)
    if not peer:
        return (f"Server GRE address: {c['address']}\n"
                "Automatic peer IP generation requires a /30 link.\n"
                "Set corresponding address on MikroTik manually.")
    net = ipaddress.IPv4Interface(c["address"]).network
    return (f"Tunnel: {c['name']}\nServer GRE: {c['address']}\n"
            f"MikroTik GRE: {peer}/30\nNetwork: {net}\n\n"
            "Run in MikroTik RouterOS terminal (replace GRE_NAME):\n"
            f"/ip address add address={peer}/30 interface=GRE_NAME\n\n"
            f"MikroTik can ping server inner IP: {ipaddress.IPv4Interface(c['address']).ip}\n"
            "For Internet through server, configure MikroTik routing to the GRE server\n"
            "using a separate routing table/policy first; keep the public GRE endpoint\n"
            "reachable via WAN, or the tunnel can route itself into a loop.\n"
            f"Server NAT: {'ENABLED' if c['internet']['enabled'] else 'DISABLED'}; "
            f"WAN: {c['internet']['wan'] or '(not set)'}\n"
            f"Allowed NAT sources: {', '.join(c['internet']['sources']) or '(none)'}\n"
            f"Missing client LAN routes: {', '.join(missing_client_routes(c)) or '(none)'}\n"
            "New GRE profiles set up NAT and LAN routes during creation.\n")


def isolated_live_update(name, old_rules, new_profile):
    """Update per-GRE policy fail-closed without removing FORWARD hooks.

    A temporary first-rule DROP stays active throughout modifications. On any
    rollback failure, leave it in place (manual recovery required).
    """
    chain = firewall_chain(name)
    new_rules = isolated_firewall_rules(new_profile)
    old_inner = [r for r in old_rules if r.get("chain") == chain and "spec" in r
                 and "-j" in r["spec"] and r["spec"][-1] != "DROP"]
    new_inner = [r for r in new_rules if r.get("chain") == chain and "spec" in r
                 and r["spec"][-1] != "DROP"]
    old_nat = [r for r in old_rules if r.get("table") == "nat"]
    new_nat = [r for r in new_rules if r.get("table") == "nat"]
    for direction in ("-i", "-o"):
        hook = next((r for r in old_rules if r.get("chain") == "FORWARD"
                     and r["spec"][0] == direction), None)
        if hook is None or run(iptables_spec("filter", "FORWARD", hook["spec"], "-C"),
                               check=False).returncode != 0:
            raise GreError("Missing isolation hook; run firewall-reconcile before bulk NAT")
    if _chain_current_rules("filter", chain) is None:
        raise GreError("Missing isolation chain; run firewall-reconcile first")
    lock = ["-m", "comment", "--comment", f"gre-manager:{name}:maintenance", "-j", "DROP"]
    run(["iptables", "-w", "-t", "filter", "-I", chain, "1"] + lock)
    added_inner, added_nat = [], []
    removed_inner, removed_nat = [], []
    try:
        for rule in old_nat:
            if run(iptables_spec("nat", "POSTROUTING", rule["spec"], "-C"),
                   check=False).returncode == 0:
                run(iptables_spec("nat", "POSTROUTING", rule["spec"], "-D"))
                removed_nat.append(rule)
        for rule in old_inner:
            run(iptables_spec("filter", chain, rule["spec"], "-D"))
            removed_inner.append(rule)
        for rule in reversed(new_inner):
            run(["iptables", "-w", "-t", "filter", "-I", chain, "2"] + rule["spec"])
            added_inner.append(rule)
        for rule in new_nat:
            if run(iptables_spec("nat", "POSTROUTING", rule["spec"], "-C"),
                   check=False).returncode != 0:
                run(["iptables", "-w", "-t", "nat", "-I", "POSTROUTING", "1"] + rule["spec"])
                added_nat.append(rule)
    except Exception as exc:
        problems = []
        for rule in reversed(added_nat + added_inner):
            try:
                run(iptables_spec(rule["table"], rule["chain"], rule["spec"], "-D"))
            except Exception as e:
                problems.append(str(e))
        for rule in reversed(removed_inner):
            try:
                run(["iptables", "-w", "-t", "filter", "-I", chain, "2"] + rule["spec"])
            except Exception as e:
                problems.append(str(e))
        for rule in removed_nat:
            try:
                run(["iptables", "-w", "-t", "nat", "-I", "POSTROUTING", "1"] + rule["spec"])
            except Exception as e:
                problems.append(str(e))
        if not problems:
            run(iptables_spec("filter", chain, lock, "-D"))
        raise GreError(f"Isolated live update failed: {exc}; "
                       f"rollback issues: {problems or 'none'}; "
                       f"{'TRAFFIC BLOCKED: repair chain manually' if problems else 'old policy restored'}") from exc
    run(iptables_spec("filter", chain, lock, "-D"))
    return new_rules


def live_nat_update(name, new_profile):
    """Apply only GRE Manager's firewall rules, without restarting the GRE link.

    Changes are tracked in /run ownership state. Never change another link's
    rules and never flush an iptables chain.
    """
    if not active(name):
        return False
    state = runtime_read(name)
    if not live_interface(name):
        raise GreError(f"Active service {name} has no GRE interface")
    info = json.loads(run(["ip", "-j", "link", "show", "dev", name]).stdout)[0]
    if info["ifindex"] != state["ifindex"]:
        raise GreError(f"GRE interface {name} changed owner; refusing NAT update")
    old_rules = state.get("nat_rules", [])
    new_rules = internet_firewall_rules(new_profile)
    if old_rules == new_rules:
        return False
    if new_profile["internet"]["enabled"]:
        prepare_internet(new_profile)
    if (state.get("nat_rules", []) and
            old_rules[0].get("kind") == "chain" and
            new_profile.get("firewall_mode") in ("isolated", "isolated-pass")):
        # Persist state only after all changes have been installed successfully.
        new_rules = isolated_live_update(name, old_rules, new_profile)
        runtime_write(new_profile, new_rules)
        return True
    removed = []
    added = []
    try:
        # Isolated chains contain DROP even when Internet/NAT is off.
        remove_internet(old_rules)
        removed = list(old_rules)
        if new_rules:
            added = install_internet(new_profile)
        # Preserve ownership token and active ip rule state; only NAT changes.
        state["nat_rules"] = added
        rp = runtime_path(name)
        fd, tmp = tempfile.mkstemp(prefix=".natstate-", dir=str(STATE))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, rp)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    except Exception as exc:
        remove_internet(added)
        issues = []
        if removed:
            try:
                # Reconstruct from original applied rules; no config-file assumptions.
                for record in removed:
                    if record.get("kind") == "chain":
                        chain = record["chain"]
                        if _chain_current_rules("filter", chain) is None:
                            run(["iptables", "-w", "-t", "filter", "-N", chain])
                    else:
                        table, chain, spec = record["table"], record["chain"], record["spec"]
                        if run(iptables_spec(table, chain, spec, "-C"), check=False).returncode:
                            operation = "-I" if record.get("insert") else "-A"
                            params = ["1"] if record.get("insert") else []
                            run(["iptables", "-w", "-t", table, operation, chain] + params + spec)
            except Exception as rollback_exc:
                issues.append(str(rollback_exc))
        raise GreError(f"Live NAT update failed on {name}: {exc}; rollback issues: {issues or 'none'}") from exc
    return True


def bulk_security_plan(targets, mode):
    if mode not in ("isolated", "isolated-pass", "legacy"):
        raise GreError("Firewall mode must be isolated, isolated-pass or legacy")
    targets = list(targets)
    if not targets or len(set(targets)) != len(targets):
        raise GreError("Select one or more unique managed GRE tunnels")
    before, after = {}, {}
    for name in targets:
        c=load(name)
        if c["firewall_mode"] != mode:
            before[name]=c
            after[name]=validate(dict(c,firewall_mode=mode))
    return before, after


def bulk_security(targets, mode, apply=False):
    """Mass change firewall policy. Live --apply needs systemd GRE restart."""
    old, updated = bulk_security_plan(targets, mode)
    if not updated:
        return {"changed":[], "restarted":[], "backup":None}
    active_before = [n for n in updated if active(n)]
    backup=safety_backup("before-bulk-security")
    restarted=[]
    try:
        for cfg in updated.values():
            save(cfg)
        if apply:
            for n in active_before:
                run(["systemctl","restart",unit(n)])
                restarted.append(n)
    except Exception as e:
        issues=[]
        for cfg in old.values():
            try: save(cfg)
            except Exception as err: issues.append(str(err))
        for n in active_before if apply else []:
            try: run(["systemctl","restart",unit(n)])
            except Exception as err: issues.append(str(err))
        raise GreError(f"Bulk security change failed: {e}; rollback problems: {issues}") from e
    return {"changed":sorted(updated), "restarted":restarted, "backup":backup,
            "pending_restart":sorted(set(updated)-set(restarted))}


def bulk_security_ui():
    tunnel_names=names()
    if not tunnel_names:
        msg("No managed tunnels")
        return
    mode=menu("Bulk GRE firewall isolation", "Select security mode for managed GRE",[
        ("isolated","ISOLATED: accept allowed traffic, drop other forwarding"),
        ("isolated-pass","ISOLATED-PASS: honor downstream GRE-FORWARD policies"),
        ("legacy","LEGACY: compatibility mode (not isolated)"),
    ])
    if not mode:
        return
    scope=menu("Bulk GRE isolation scope", "Which tunnels?",[
        ("all","ALL managed tunnels"),("select","Specific tunnels (checkboxes)")])
    if not scope:
        return
    targets=tunnel_names if scope=="all" else select_tunnels_checklist(tunnel_names)
    if not targets:
        return
    old, changes=bulk_security_plan(targets,mode)
    textbox("Firewall isolation PREVIEW", "\n".join(
        [f"Change {len(changes)} of {len(targets)} GRE to {mode}:"]+
        [f"{n}: {old[n]['firewall_mode']} -> {mode}; ACTIVE={active(n)}" for n in changes]+
        ["", "Changes saved to JSON only until restart. --apply will restart GRE!",
         "For existing old firewall rules, run audit before cutover."]))
    if not changes or not confirm("Save firewall mode for selected GRE? A ZIP backup is created."):
        return
    live=any(active(n) for n in changes)
    apply=live and confirm("RESTART affected ACTIVE GRE now? Traffic/SSH over these links WILL DROP briefly.")
    msg(json.dumps(bulk_security(targets,mode,apply=apply),indent=2),"Security mode updated")


def bulk_internet_plan(targets, turn_on, wan=""):
    """Return (old, updated) profiles, validating the entire selection up front."""
    targets = list(targets)
    if not targets or len(targets) != len(set(targets)):
        raise GreError("Select at least one unique managed GRE tunnel")
    old, changed = {}, {}
    for name in targets:
        c = load(name)
        settings = dict(c["internet"])
        if turn_on:
            peer = peer_address(c)
            if not settings["sources"]:
                if not peer:
                    raise GreError(f"{name}: no /30 peer available; configure NAT sources manually")
                settings["sources"] = [peer + "/32"]
            settings["wan"] = wan or settings["wan"] or guess_wan()
            settings["enabled"] = True
        else:
            settings["enabled"] = False
        proposed = validate(dict(c, internet=settings))
        if proposed != c:
            old[name] = c
            changed[name] = proposed
    return old, changed


def bulk_internet(targets, turn_on, wan="", apply=False):
    """Mass change NAT profiles with automatic backup, best-effort rollback.

    With apply=True update scoped firewall rules live, no GRE restarts.
    """
    old, updated = bulk_internet_plan(targets, turn_on, wan)
    if not updated:
        return {"count": 0, "changed": [], "live_applied": [],
                "pending": [], "safety_backup": None}
    if apply and turn_on:
        if not shutil.which("iptables"):
            raise GreError("iptables is required: apt install iptables")
        for name, cfg in updated.items():
            if active(name) and not live_interface(cfg["internet"]["wan"]):
                raise GreError(f"WAN {cfg['internet']['wan']} not present for {name}")
    active_targets = [n for n in updated if active(n)]
    backup = safety_backup("before-bulk-internet")
    applied = []
    try:
        for cfg in updated.values():
            save(cfg)
        if apply:
            for name in active_targets:
                live_nat_update(name, updated[name])
                applied.append(name)
    except Exception as exc:
        issues = []
        for cfg in old.values():
            try:
                save(cfg)
            except Exception as rollback_exc:
                issues.append(f"profile {cfg['name']}: {rollback_exc}")
        if apply:
            for name in active_targets:
                try:
                    live_nat_update(name, old[name])
                except Exception as rollback_exc:
                    issues.append(f"firewall {name}: {rollback_exc}")
        raise GreError(f"Bulk NAT operation failed: {exc}. Rollback issues: "
                       f"{issues or 'none'}; backup: {backup}") from exc
    return {"count": len(updated), "changed": sorted(updated),
            "live_applied": applied,
            "pending": sorted(n for n in updated if n not in applied),
            "safety_backup": backup}


def update_internet(before, after, apply=False):
    """Update one profile, with backup and best-effort live-firewall rollback."""
    if before["name"] != after["name"]:
        raise GreError("NAT update cannot rename an interface")
    if before == after:
        return {"changed": False, "live_applied": False}
    was_active = active(before["name"])
    archive = safety_backup("before-internet")
    save(after)
    try:
        if apply and was_active:
            live_nat_update(before["name"], after)
    except Exception as e:
        save(before)
        issues = []
        try:
            live_nat_update(before["name"], before)
        except Exception as rollback_exc:
            issues.append(str(rollback_exc))
        raise GreError(f"NAT configuration failed: {e}. Old config restored; "
                       f"live rollback: {issues or 'OK'}. Backup: {archive}") from e
    return {"changed": True, "live_applied": bool(apply and was_active),
            "pending_apply": bool(was_active and not apply),
            "backup": archive}


def pool_ui():
    current = read_pool()
    try:
        next_pair = allocate_pair(current)
        next_server, next_client = next_pair["server"], next_pair["peer"]
    except GreError:
        next_server, next_client = "pool exhausted", "pool exhausted"
    chosen = input_prompt("GRE /30 address pool",
                          f"Current pool: {current}\n"
                          f"Next server: {next_server}\n"
                          f"Next MikroTik: {next_client}\n\n"
                          "Enter a NEW private subnet for auto-allocation.", current)
    if chosen is None or chosen == current:
        return
    candidate = pool_validate(chosen)
    pair = allocate_pair(candidate)
    if confirm(f"New GRE pool: {candidate}\n"
               f"Next server: {pair['server']}\nNext client: {pair['peer']}\n\n"
               "Existing GRE tunnel IPs will NOT be changed. Save this pool?"):
        write_pool(candidate)
        msg("GRE allocation pool updated: " + candidate)


def internet_ui(name):
    old = load(name)
    settings = old["internet"]
    peer = peer_address(old)
    default_sources = ",".join(settings["sources"]) or (peer + "/32" if peer else "")
    values = form("Internet sharing through this GRE",
                  "NAT is enabled by DEFAULT for newly created tunnels. WAN is SERVER uplink.\n"
                  "Use comma-separated sources; include LANs behind MikroTik if needed.", [
        ("Enable NAT (yes/no)", "yes" if settings["enabled"] else "no"),
        ("WAN egress interface", settings["wan"] or guess_wan()),
        ("Client sources CIDR (comma)", default_sources),
    ])
    if values is None:
        return
    enabled_text, wan, sources_text = values
    if enabled_text.lower() not in ("yes", "no", "y", "n"):
        raise GreError("Enable NAT field must be yes or no")
    setting = {"enabled": enabled_text.lower() in ("yes", "y"),
               "wan": wan.strip(),
               "sources": [x.strip() for x in sources_text.split(",") if x.strip()]}
    updated = validate(dict(old, internet=setting))
    missing = missing_client_routes(updated) if updated["internet"]["enabled"] else []
    lines = [f"Tunnel: {name}",
             f"NAT enabled: {updated['internet']['enabled']}",
             f"Outbound WAN: {updated['internet']['wan']}",
             f"Allowed client subnets: {', '.join(updated['internet']['sources'])}",
             f"Forwarding currently: {forwarding_status()}",
             f"Missing profile routes to client LANs: {', '.join(missing) or 'none'}",
             "", "If LANs are behind MikroTik, server needs return routes through GRE:"]
    lines.extend(f"  {net} -> dev {name} (add via Routes menu)" for net in missing)
    lines.extend(["", "Active tunnels can apply firewall changes LIVE, without GRE restart.",
                  "On start with NAT enabled, IP forwarding + scoped iptables rules are installed.",
                  "When NAT is disabled the global ip_forward setting is NOT reverted."])
    textbox("Review GRE NAT settings", "\n".join(lines))
    if updated == old:
        return
    if not confirm("Save these Internet/NAT settings for " + name + "?\n"
                   "A full safety backup will be created first."):
        return
    apply = active(name) and confirm(
        "Apply NAT/firewall changes LIVE now?\n"
        "The GRE interface will NOT be restarted.")
    result = update_internet(old, updated, apply)
    msg(json.dumps(result, indent=2), "Internet settings saved")


def select_tunnels_checklist(tunnels):
    """dialog --separate-output gives one selected tag per line."""
    args = ["--title", "Choose GRE tunnels", "--separate-output", "--checklist",
            "Space: select/deselect; Enter: continue. No tunnels selected by default.",
            "24", "106", "16"]
    for name in tunnels:
        c = load(name)
        summary = (f"{'ON' if c['internet']['enabled'] else 'OFF'} "
                   f"| {c['internet']['wan'] or '-':10} "
                   f"| {c['local']} -> {c['remote']}")
        args += [name, summary[:75], "off"]
    p = dlg(args)
    if p.returncode != 0:
        return None
    return [x.strip() for x in p.stdout.splitlines() if x.strip()]


def bulk_internet_ui():
    tunnels = names()
    if not tunnels:
        msg("There are no managed GRE tunnels yet.", "Bulk Internet/NAT")
        return
    action = menu("Bulk Internet / NAT", "Change NAT/firewall settings for multiple GRE tunnels", [
        ("on", "ENABLE Internet NAT/forwarding for selected GRE"),
        ("off", "DISABLE Internet NAT/forwarding for selected GRE"),
    ])
    if action is None:
        return
    scope = menu("Select GRE tunnels", "Which tunnels should be changed?", [
        ("all", f"ALL managed GRE tunnels ({len(tunnels)})"),
        ("select", "Select specific GRE tunnels using checkboxes"),
    ])
    if scope is None:
        return
    selected = tunnels if scope == "all" else select_tunnels_checklist(tunnels)
    if selected is None:
        return
    if not selected:
        msg("Nothing selected; no changes made")
        return
    wan = ""
    if action == "on":
        wan_field = input_prompt("WAN for selected tunnels",
                   "WAN interface for ALL selected tunnels (blank = keep existing WAN, "
                   "otherwise auto-detect).\n"
                   "Server-side WAN is used to MASQUERADE client traffic.", "")
        if wan_field is None:
            return
        wan = wan_field.strip()
        if wan and not IFNAME_RE.fullmatch(wan):
            raise GreError("Invalid WAN interface name")
        if wan and not live_interface(wan):
            raise GreError(f"WAN interface {wan} does not exist")
    old, changed = bulk_internet_plan(selected, action == "on", wan)
    lines = [f"Action: {'ENABLE' if action == 'on' else 'DISABLE'} NAT",
             f"Selected: {len(selected)}; actual changes: {len(changed)}",
             "", "Changes by tunnel:"]
    for name in selected:
        if name not in changed:
            lines.append(f"  {name}: already in desired state / no change")
            continue
        updated = changed[name]
        status = "ACTIVE" if active(name) else "STOPPED"
        lines.append(f"  {name} [{status}]: {'ON' if old[name]['internet']['enabled'] else 'OFF'} -> "
                     f"{'ON' if updated['internet']['enabled'] else 'OFF'}")
        if action == "on":
            lines.append(f"     WAN {updated['internet']['wan']}; "
                         f"sources {', '.join(updated['internet']['sources'])}")
            missing = missing_client_routes(updated)
            if missing:
                lines.append("     MISSING client LAN routes: " + ", ".join(missing))
    lines += ["", "A ZIP backup is created before changes.",
              "On active tunnels, firewall rules can be changed LIVE without GRE restart.",
              "On stopped tunnels, rules will activate on next start.",
              "Disabling NAT does not reset global net.ipv4.ip_forward."]
    textbox("Review bulk Internet changes", "\n".join(lines))
    if not changed:
        msg("All selected profiles are already configured; nothing to do")
        return
    if not confirm(f"Save NAT changes for {len(changed)} GRE tunnel(s)?"):
        return
    live = any(active(n) for n in changed)
    apply = live and confirm(
        "Apply firewall changes NOW on ACTIVE GRE tunnels?\n"
        "No GRE interfaces will be restarted.\n"
        "No = save changes only, apply on next tunnel restart.",
        "Live NAT apply")
    result = bulk_internet(selected, action == "on", wan, apply)
    msg(json.dumps(result, ensure_ascii=False, indent=2), "Bulk NAT complete")


def acl_ui():
    action=menu("GRE protocol-47 INPUT ACL", "Advanced: only for exclusive underlay addresses", [
        ("preview","Preview which remote GRE IPs may reach this public address"),
        ("on","ENABLE managed INPUT protocol-47 ACL (advanced)"),
        ("off","DISABLE managed INPUT protocol-47 ACL"),
    ])
    if action is None:
        return
    if action == "off":
        if confirm("Disable GRE INPUT access restriction? This allows other firewall rules to decide."):
            underlay_acl_disable()
            msg("Optional GRE INPUT restriction disabled")
        return
    endpoint=input_prompt("GRE underlay local IPv4", "IPv4 assigned to this Linux host",outbound_ipv4())
    if endpoint is None:
        return
    wan=input_prompt("GRE underlay WAN", "Physical WAN interface receiving GRE protocol 47",guess_wan())
    if wan is None:
        return
    plan=underlay_acl_plan(endpoint,wan)
    textbox("INPUT ACL preview", json.dumps(plan,indent=2))
    if action == "on" and confirm("EXCLUSIVE WAN ADDRESS ONLY. Existing unknown GRE peers may lose access!\n"
                                   "Enable this protocol-47 whitelist after reviewing the migration?",
                                   "Final confirmation"):
        underlay_acl_enable(endpoint,wan)
        msg("GRE INPUT ACL enabled. Inspect systemctl status gre-manager-input-acl")


def stage_ui():
    candidates = [n for n in live_gre_inventory() if n not in names()]
    if not candidates:
        msg("No unmanaged kernel GRE interfaces were detected")
        return
    name = menu("Stage existing Linux GRE", "Read-only scan; select GRE to stage as a profile", [(n,n) for n in candidates])
    if not name:
        return
    plan = staged_live_profile(name)
    textbox("Migration preview (NO takeover)", json.dumps(plan, indent=2))
    if confirm(f"Create INACTIVE profile for {name}?\n"
               "Existing live GRE / old scripts stay untouched.\n"
               "You must cut over ownership manually before starting new service."):
        stage_live(name)
        msg(f"Staged {name}. Do NOT start gre-manager@{name} until old owner stopped and "
            "kernel interface removed. Configure NAT/security/routes before cutover.")


def audit_ui():
    pool = read_pool()
    alloc = external_address_occupancy(pool)
    report = firewall_audit()
    inventory = sorted(live_gre_inventory())
    report["address_pool"] = pool
    report["occupied_networks"] = [(str(net), evidence) for net,evidence in alloc]
    report["unmanaged_gre"] = [name for name in inventory if name not in names()]
    textbox("GRE / IP / firewall audit", json.dumps(report, indent=2))


def help_ui():
    msg("MAIN MENU:\n"
        "- Create a GRE profile; then select its name below to manage it.\n"
        "- New GRE: NAT enabled by default; enter optional client LAN routes.\n"
        "- Bulk Internet/NAT: all or checklist selection; LIVE apply.\n"
        "- Existing profile submenu has routes, rules, start/stop, edit, logs, ping.\n"
        "- Network overview and Linux tunnels are read-only.\n"
        "- Backup/restore includes all MANAGED profiles, their routes, rules, boot flags.\n"
        "- Bulk local IP supports filter by old IP and optional live apply.\n"
        "- GRE /30 pool allocator assigns a unique server/client pair.\n"
        "- Internet sharing enables scoped forwarding+MASQUERADE per tunnel.\n"
        "- At new tunnel creation, client LAN return routes are added automatically.\n"
        "- For older profiles, manually configure missing client LAN routes.\n\n"
        "LOCAL IPv4: Automatically suggested from 'ip -4 route get'. "
        "For a multi-WAN server, source for the actual remote peer is checked "
        "after editing the form.\n\n"
        "Public IPv4 observed via HTTPS can differ behind NAT/proxies. "
        "Do NOT enter a NAT external IPv4 as GRE local unless it is actually "
        "configured on the server. GRE is IP protocol 47, not TCP/UDP port 47.\n\n"
        "Only GRE tunnels created by this utility can be managed. "
        "Other GRE devices are shown read-only.", "Help / GRE Manager")


def ui():
    if not sys.stdin.isatty():
        raise GreError("Run GRE Manager in an interactive terminal (SSH is fine)")
    if not shutil.which("dialog"):
        raise GreError("Missing dialog: apt install dialog")
    if not UNIT_PATH.exists():
        raise GreError("Initialize first: sudo gre-manager init")
    while True:
        tunnels = names()
        opts = [
            ("+", "Create GRE tunnel"),
            ("@backup", "Backup ALL managed GRE tunnels to ZIP"),
            ("@restore", "Restore tunnels from ZIP (another server)"),
            ("@bulk", "Bulk update local IPv4 in GRE tunnels"),
            ("@internet", "Bulk Internet/NAT: enable/disable ALL or selected GRE"),
            ("@security", "Bulk GRE firewall isolation: ALL or selected"),
            ("@audit", "Host audit: GRE addresses, legacy firewall, conflicts"),
            ("@stage", "Stage existing Linux GRE profiles (NO takeover)"),
            ("@acl", "GRE public-underlay INPUT ACL (advanced, opt-in)"),
            ("@pool", "GRE client /30 address pool"),
            ("@net", "Host network: public/local IP, interfaces, routes, rules"),
            ("@gre", "Show all kernel GRE/IP tunnels (read-only)"),
            ("@help", "Help and usage"),
        ]
        for n in tunnels:
            try:
                c = load(n)
                state = "UP" if active(n) else "DOWN"
                opts.append((n, f"[{state}] {c['local']} > {c['remote']}  "
                                f"routes:{len(c['routes'])}; manage tunnel"))
            except Exception:
                opts.append((n, "[INVALID CONFIG]"))
        opts.append(("@quit", "Exit"))
        hint = (f"Configured tunnels: {len(tunnels)}. "
                "Select a tunnel to edit routes, rules, autostart etc.")
        choice = menu("GRE Manager", hint, opts)
        if choice in (None, "@quit"):
            break
        if choice == "+":
            safe(new_tunnel)
        elif choice == "@backup":
            safe(backup_ui)
        elif choice == "@restore":
            safe(restore_ui)
        elif choice == "@bulk":
            safe(bulk_local_ui)
        elif choice == "@internet":
            safe(bulk_internet_ui)
        elif choice == "@security":
            safe(bulk_security_ui)
        elif choice == "@audit":
            safe(audit_ui)
        elif choice == "@stage":
            safe(stage_ui)
        elif choice == "@acl":
            safe(acl_ui)
        elif choice == "@pool":
            safe(pool_ui)
        elif choice == "@net":
            safe(host_network_ui)
        elif choice == "@gre":
            safe(unmanaged_ui)
        elif choice == "@help":
            safe(help_ui)
        else:
            safe(lambda: tunnel_ui(choice))


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print("""GRE Manager v%s | Debian / Ubuntu
Usage:
  sudo gre-manager                       # interactive TUI
  sudo gre-manager init                  # install systemd unit
  sudo gre-manager backup /root/gre.zip  # save all managed GRE tunnels
  sudo gre-manager pool [NEW_POOL_CIDR]     # show/change GRE /30 allocation pool
  sudo gre-manager audit                     # readonly legacy firewall / address audit
  sudo gre-manager acl preview --local IPV4 --wan ens3
  sudo gre-manager acl enable --local IPV4 --wan ens3 --exclusive-underlay --commit
  sudo gre-manager acl disable --commit
  sudo gre-manager acl reconcile             # update allowed peers / restored INPUT hook
  sudo gre-manager stage-live NAME [--commit] # preview or stage existing Linux GRE
  sudo gre-manager firewall-reconcile NAME  # restore missing owned iptables rules
  sudo gre-manager bulk-security --mode isolated --all [--commit] [--apply]
  sudo gre-manager allocate [POOL_CIDR]    # preview next free server/client /30
  sudo gre-manager peer TUNNEL             # RouterOS GRE IP/route instructions
  sudo gre-manager internet TUNNEL         # show NAT/forwarding status and config
  sudo gre-manager internet TUNNEL --enable --wan eth0 --sources 10.255.10.0/30[,192.168.88.0/24] [--commit] [--apply]
  sudo gre-manager internet TUNNEL --disable [--commit] [--apply]
  sudo gre-manager bulk-internet --enable --all [--wan WAN] [--commit] [--apply]
  sudo gre-manager bulk-internet --disable --tunnels gre1,gre2 [--commit] [--apply]
  sudo gre-manager restore BACKUP.zip [--local IPv4] [--replace]
                            [--enable-saved] [--wan WAN] [--commit]
  sudo gre-manager bulk-local NEW_IP [--from OLD_IP]
                            [--allow-unassigned] [--apply] [--commit]

Restore/bulk commands are PREVIEW-ONLY unless --commit is specified.
bulk-internet --apply updates firewall rules LIVE, with no GRE restarts.
bulk-local --apply still restarts affected active tunnels (SSH risk).
Restoring never starts/restarts tunnels. Only managed GRE profiles are included.
Automatic pre-change ZIP backups go to /var/backups/gre-manager.
""" % VERSION)
        return
    if os.geteuid() != 0:
        raise GreError("Root required: sudo gre-manager")
    op = sys.argv[1] if len(sys.argv) > 1 else "ui"
    if op == "init" and len(sys.argv) == 2:
        setup()
        print("GRE Manager systemd unit installed. Start with: sudo gre-manager")
    elif op in ("_up", "_down") and len(sys.argv) == 3:
        (up if op == "_up" else down)(sys.argv[2])
    elif op == "ui" and len(sys.argv) == 1:
        ui()
    elif op == "acl":
        parser = argparse.ArgumentParser(prog="gre-manager acl")
        parser.add_argument("action", choices=["preview", "enable", "disable", "reconcile"])
        parser.add_argument("--local", default="")
        parser.add_argument("--wan", default="")
        parser.add_argument("--exclusive-underlay", action="store_true")
        parser.add_argument("--commit", action="store_true")
        args=parser.parse_args(sys.argv[2:])
        if args.action == "preview":
            print(json.dumps(underlay_acl_plan(args.local,args.wan),indent=2))
        elif args.action == "enable":
            if not (args.commit and args.exclusive_underlay):
                raise GreError("Enable requires --commit --exclusive-underlay, and verified dedicated underlay")
            print(json.dumps(underlay_acl_enable(args.local,args.wan),indent=2))
        elif args.action == "reconcile":
            if not args.commit:
                raise GreError("Reconcile requires --commit")
            print(json.dumps(underlay_acl_reconcile(),indent=2))
        else:
            if not args.commit:
                raise GreError("Disable requires --commit")
            underlay_acl_disable()
            print("Managed GRE protocol-47 INPUT ACL disabled")
    elif op == "_acl_restore" and len(sys.argv) == 2:
        underlay_acl_restore()
    elif op == "_acl_clear" and len(sys.argv) == 2:
        underlay_acl_clear()
    elif op == "audit" and len(sys.argv) == 2:
        report = firewall_audit()
        pool = read_pool()
        report["address_pool"] = pool
        report["occupied_networks"] = [(str(net), why) for net, why in external_address_occupancy(pool)]
        report["unmanaged_gre"] = sorted(set(live_gre_inventory()) - set(names()))
        print(json.dumps(report, indent=2))
    elif op == "bulk-security":
        parser=argparse.ArgumentParser(prog="gre-manager bulk-security")
        parser.add_argument("--mode",choices=["isolated","isolated-pass","legacy"],required=True)
        group=parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--all",action="store_true")
        group.add_argument("--tunnels",default="")
        parser.add_argument("--commit",action="store_true")
        parser.add_argument("--apply",action="store_true")
        args=parser.parse_args(sys.argv[2:])
        if args.apply and not args.commit:
            raise GreError("--apply requires --commit")
        targets=names() if args.all else [n.strip() for n in args.tunnels.split(",") if n.strip()]
        old, updated=bulk_security_plan(targets,args.mode)
        plan={"mode":"commit" if args.commit else "preview",
              "target_firewall_mode":args.mode,"selected":targets,
              "changes":{n:{"old":old[n]["firewall_mode"],
                             "new":updated[n]["firewall_mode"],"active":active(n)}
                         for n in updated}}
        if args.commit:
            plan["result"]=bulk_security(targets,args.mode,apply=args.apply)
        print(json.dumps(plan,indent=2))
    elif op == "stage-live":
        parser = argparse.ArgumentParser(prog="gre-manager stage-live")
        parser.add_argument("name")
        parser.add_argument("--commit", action="store_true")
        args = parser.parse_args(sys.argv[2:])
        result = stage_live(args.name) if args.commit else staged_live_profile(args.name)
        print(json.dumps({"mode": "commit" if args.commit else "preview", **result}, indent=2))
    elif op == "firewall-reconcile" and len(sys.argv) == 3:
        print(json.dumps(firewall_reconcile(sys.argv[2]), indent=2))
    elif op == "pool":
        if len(sys.argv) == 2:
            print(read_pool())
        elif len(sys.argv) == 3:
            print(write_pool(sys.argv[2]))
        else:
            raise GreError("Usage: gre-manager pool [PRIVATE_CIDR]")
    elif op == "allocate":
        print(json.dumps(allocate_pair(sys.argv[2] if len(sys.argv) == 3
                                        else read_pool()), indent=2))
    elif op == "peer" and len(sys.argv) == 3:
        print(mikrotik_notes(load(sys.argv[2])))
    elif op == "bulk-internet":
        parser = argparse.ArgumentParser(prog="gre-manager bulk-internet")
        action = parser.add_mutually_exclusive_group(required=True)
        action.add_argument("--enable", action="store_true")
        action.add_argument("--disable", action="store_true")
        selection = parser.add_mutually_exclusive_group(required=True)
        selection.add_argument("--all", action="store_true")
        selection.add_argument("--tunnels", help="comma-separated managed GRE names")
        parser.add_argument("--wan", default="", help="optional server WAN override")
        parser.add_argument("--commit", action="store_true")
        parser.add_argument("--apply", action="store_true", help="live firewall update")
        args = parser.parse_args(sys.argv[2:])
        if args.apply and not args.commit:
            raise GreError("--apply requires --commit")
        if args.disable and args.wan:
            raise GreError("--wan only applies to --enable")
        selected = names() if args.all else [x.strip() for x in args.tunnels.split(",") if x.strip()]
        old, changed = bulk_internet_plan(selected, args.enable, args.wan)
        summary = {"mode": "commit" if args.commit else "preview",
                   "action": "enable" if args.enable else "disable",
                   "selected": selected,
                   "changes": {n: {"before": old[n]["internet"],
                                   "after": cfg["internet"], "active": active(n),
                                   "missing_client_routes": missing_client_routes(cfg) if args.enable else []}
                               for n, cfg in changed.items()},
                   "live_apply_requested": args.apply}
        if args.commit:
            summary["result"] = bulk_internet(selected, args.enable, args.wan, args.apply)
        print(json.dumps(summary, indent=2))
    elif op == "internet":
        parser = argparse.ArgumentParser(prog="gre-manager internet")
        parser.add_argument("name")
        action = parser.add_mutually_exclusive_group()
        action.add_argument("--enable", action="store_true")
        action.add_argument("--disable", action="store_true")
        parser.add_argument("--wan", default="")
        parser.add_argument("--sources", default="", help="comma-separated IPv4 CIDRs")
        parser.add_argument("--commit", action="store_true")
        parser.add_argument("--apply", action="store_true")
        args = parser.parse_args(sys.argv[2:])
        existing = load(args.name)
        if args.enable:
            sources = [x.strip() for x in args.sources.split(",") if x.strip()]
            if not sources:
                peer = peer_address(existing)
                if not peer:
                    raise GreError("Supply --sources for non-/30 GRE addresses")
                sources = [peer + "/32"]
            setting = {"enabled": True,
                       "wan": args.wan or existing["internet"]["wan"] or guess_wan(),
                       "sources": sources}
        elif args.disable:
            setting = dict(existing["internet"], enabled=False)
        else:
            if args.commit or args.apply or args.wan or args.sources:
                raise GreError("Choose --enable or --disable when changing NAT")
            print(json.dumps({"internet": existing["internet"],
                              "ip_forward": forwarding_status()}, indent=2))
            return
        updated = validate(dict(existing, internet=setting))
        summary = {"mode": "commit" if args.commit else "preview",
                   "before": existing["internet"], "after": updated["internet"],
                   "client_routes_missing_in_profile": missing_client_routes(updated),
                   "live_apply_requested": args.apply}
        if args.apply and not args.commit:
            raise GreError("--apply requires --commit")
        if args.commit:
            summary["result"] = update_internet(existing, updated, args.apply)
        print(json.dumps(summary, indent=2))
    elif op == "backup":
        parser = argparse.ArgumentParser(prog="gre-manager backup")
        parser.add_argument("archive")
        args = parser.parse_args(sys.argv[2:])
        print(json.dumps(backup_all(args.archive), indent=2))
    elif op == "restore":
        parser = argparse.ArgumentParser(prog="gre-manager restore")
        parser.add_argument("archive")
        parser.add_argument("--local", default="", help="local IP of target server")
        parser.add_argument("--replace", action="store_true", help="overwrite managed profiles")
        parser.add_argument("--enable-saved", action="store_true", help="restore boot enabled flags")
        parser.add_argument("--wan", default="", help="override NAT WAN interface on new server")
        parser.add_argument("--commit", action="store_true", help="write validated profiles")
        args = parser.parse_args(sys.argv[2:])
        profiles, boot, conflicts = restore_plan(args.archive, args.local, args.replace, args.wan)
        summary = {"mode": "commit" if args.commit else "preview", "count": len(profiles),
                   "existing_to_overwrite": conflicts,
                   "local_addresses": {n: c["local"] for n, c in profiles.items()},
                   "saved_autostart": boot, "enable_saved": args.enable_saved,
                   "nat_wan_override": args.wan or None,
                   "starts_tunnels": False}
        if args.commit:
            summary["result"] = restore_all(args.archive, args.local, args.replace,
                                             args.enable_saved, args.wan)
        print(json.dumps(summary, indent=2))
    elif op == "bulk-local":
        parser = argparse.ArgumentParser(prog="gre-manager bulk-local")
        parser.add_argument("new_ip")
        parser.add_argument("--from", dest="old_ip", default="", help="only previous local IP")
        parser.add_argument("--allow-unassigned", action="store_true", help="config-only offline staging")
        parser.add_argument("--apply", action="store_true", help="restart affected active tunnels")
        parser.add_argument("--commit", action="store_true", help="write validated profiles")
        args = parser.parse_args(sys.argv[2:])
        old, updated = bulk_plan(args.new_ip, args.old_ip)
        summary = {"mode": "commit" if args.commit else "preview", "count": len(updated),
                   "changes": {n: {"from": old[n]["local"], "to": updated[n]["local"],
                                   "active": bool(active(n))} for n in updated},
                   "restart_requested": args.apply}
        if args.commit:
            summary["result"] = bulk_local(args.new_ip, args.old_ip,
                                           args.apply, args.allow_unassigned)
        print(json.dumps(summary, indent=2))
    else:
        raise GreError("Unknown arguments; use --help")


if __name__ == "__main__":
    try:
        main()
    except (GreError, ValueError, OSError, subprocess.SubprocessError,
            json.JSONDecodeError) as err:
        print(f"GRE Manager error: {err}", file=sys.stderr)
        sys.exit(1)
