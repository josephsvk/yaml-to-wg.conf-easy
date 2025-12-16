#!/usr/bin/env python3
"""
WireGuard config + key generator (offline, no interface changes)

Goal
- Single source of truth: ./wg.yaml
- Deterministic output layout:
  - ./secrets/<server>/server_privatekey, server_publickey
  - ./secrets/<server>/peers/<peer>/{privatekey,publickey,presharedkey}
  - ./out/<server>/<server>.conf                (server wg config)
  - ./out/<server>/peers/<peer>.conf            (client wg config)

What this script does NOT do
- Does not start/stop interfaces
- Does not run wg-quick, wg syncconf, iptables, sysctl, etc.

YAML fields (minimal contract)
servers[]:
  name            (required)  -> interface name on server + folder names
  endpoint        (required)  -> public IP/DNS clients connect to
  port            (required)  -> UDP listen port on server
  address_v4      (required)  -> server VPN IP with mask, e.g. 10.1.0.1/24

  description     (optional)  -> copied into generated .conf as comments
  dns             (optional)  -> default DNS for clients (can be overridden per peer)
  client_routes_default (optional) -> default client routing (can be overridden per peer)
  peer_allowed_ips_default (optional) -> extra server AllowedIPs given to peers (host /32 is always included)

  peers[]:
    name          (required)  -> peer name + file name
    address       (required)  -> peer VPN IP (script forces /32 on client)
    peer_allowed_ips (optional) -> server-side AllowedIPs (defaults to <address>/32 + server extra)
    description   (optional)  -> copied into generated .conf as comments
    dns           (optional)  -> overrides server dns for this peer (client config only)
    client_routes (optional)  -> overrides server client_routes_default (client config only)

Legacy field names (`allowed_ips`, `client_allowed_ips`, `client_allowed_ips_default`,
`server_allowed_ips_default`) still work for backwards compatibility.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import yaml

# -----------------------------------------------------------------------------
# Paths / constants
# -----------------------------------------------------------------------------
BASE = Path(__file__).resolve().parent
CFG = BASE / "wg.yaml"
SECRETS = BASE / "secrets"
OUT = BASE / "out"

# WireGuard "name" is used in file paths. Enforce safe + predictable naming.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")

# File permission policy
DIR_MODE = 0o700
FILE_MODE = 0o600

# -----------------------------------------------------------------------------
# Shell helpers (for wg key ops only)
# -----------------------------------------------------------------------------
def sh(cmd: list[str], input_text: str | None = None) -> str:
    """
    Run a command and return stdout (trimmed).
    Aborts with a readable error if command fails.

    Used only for:
      - wg genkey
      - wg pubkey
      - wg genpsk
    """
    p = subprocess.run(
        cmd,
        input=(input_text.encode() if input_text else None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if p.returncode != 0:
        raise SystemExit(
            f"command failed: {' '.join(cmd)}\n"
            f"stdout: {p.stdout.decode().strip()}\n"
            f"stderr: {p.stderr.decode().strip()}"
        )
    return p.stdout.decode().strip()


def wg_genkey() -> str:
    """Generate WireGuard private key."""
    return sh(["wg", "genkey"])


def wg_pubkey(priv: str) -> str:
    """Derive WireGuard public key from private key."""
    return sh(["wg", "pubkey"], input_text=priv)


def wg_genpsk() -> str:
    """Generate WireGuard preshared key (PSK)."""
    return sh(["wg", "genpsk"])


# -----------------------------------------------------------------------------
# Filesystem helpers
# -----------------------------------------------------------------------------
def ensure_dir(p: Path, mode: int = DIR_MODE) -> None:
    """Create directory (and parents). Enforce permissions."""
    p.mkdir(parents=True, exist_ok=True)
    os.chmod(p, mode)


def write_secret(path: Path, value: str, mode: int = FILE_MODE) -> None:
    """
    Write a secret to disk with strict permissions.
    The directory is forced to DIR_MODE.
    """
    ensure_dir(path.parent, DIR_MODE)
    path.write_text(value.strip() + "\n", encoding="utf-8")
    os.chmod(path, mode)


def read_secret(path: Path) -> str:
    """Read a secret file."""
    return path.read_text(encoding="utf-8").strip()


# -----------------------------------------------------------------------------
# Validation / formatting
# -----------------------------------------------------------------------------
def normalize_name(name: str) -> str:
    """
    Normalize and validate any name used for folders/files.

    Allowed:
      - lower-case a-z, 0-9
      - '.', '_', '-'
      - length 1..63
    """
    n = name.strip().lower()
    if not NAME_RE.match(n):
        raise SystemExit(f"invalid name: {name!r} (allowed: a-z0-9 . _ -)")
    return n


def load_cfg() -> dict:
    """
    Load ./wg.yaml and validate the root shape.
    """
    if not CFG.exists():
        raise SystemExit(f"missing {CFG}")
    data = yaml.safe_load(CFG.read_text(encoding="utf-8")) or {}
    if "servers" not in data or not isinstance(data["servers"], list):
        raise SystemExit("wg.yaml must contain: servers: [ ... ]")
    return data


def ip_host32(ip: str) -> str:
    """
    Force an IP string to host /32 for server AllowedIPs default.
    Accepts '10.1.0.2' or '10.1.0.2/24' -> '10.1.0.2/32'
    """
    host = str(ip).split("/")[0].strip()
    return f"{host}/32"


def default_peer_allowed(ip: str) -> list[str]:
    """Default server-side allowed IPs for a peer = its single host /32."""
    return [ip_host32(ip)]


def comment_block(lines: list[str]) -> str:
    """
    Convert free-form lines into WireGuard config comments (# ...).
    Supports multiline description content.
    """
    out: list[str] = []
    for l in lines:
        for sub in str(l).splitlines():
            out.append(f"# {sub}".rstrip())
    return "\n".join(out)


def safe_list(x) -> list[str]:
    """Normalize scalar-or-list YAML values to list[str]."""
    if x is None:
        return []
    if isinstance(x, list):
        return [str(i) for i in x]
    return [str(x)]


def resolve_client_allowed(server_cfg: dict, peer_cfg: dict) -> list[str]:
    """Resolve client-side AllowedIPs with peer override -> server default -> fallback."""
    peer_override = safe_list(
        peer_cfg.get("client_routes") or peer_cfg.get("client_allowed_ips")
    )
    if peer_override:
        return peer_override

    server_default = safe_list(
        server_cfg.get("client_routes_default")
        or server_cfg.get("client_allowed_ips_default")
        or server_cfg.get("client_allowed_ips")
    )
    if server_default:
        return server_default

    return ["0.0.0.0/0", "::/0"]


def resolve_peer_allowed(server_cfg: dict, peer_cfg: dict, peer_ip: str) -> list[str]:
    """
    Resolve server-side AllowedIPs.
    Always includes the peer's own /32 unless a peer override is explicitly set.
    """
    peer_override = safe_list(
        peer_cfg.get("peer_allowed_ips")
        or peer_cfg.get("server_allowed_ips")
        or peer_cfg.get("allowed_ips")
    )
    if peer_override:
        return peer_override

    server_extra = safe_list(
        server_cfg.get("peer_allowed_ips_default")
        or server_cfg.get("server_allowed_ips_default")
    )
    base = default_peer_allowed(peer_ip)
    if server_extra:
        base.extend(server_extra)
    return base


# -----------------------------------------------------------------------------
# Renderers (server.conf and client.conf)
# -----------------------------------------------------------------------------
def render_server_conf(server: dict, server_priv: str, peers: list[dict]) -> str:
    """
    Render server-side WireGuard config:
      - [Interface] includes server private key
      - [Peer] blocks include peer public key + PSK + server AllowedIPs

    Notes:
      - server config does not include Endpoint (server doesn't need it)
      - peer descriptions are included as comments
    """
    header = [
        "=" * 78,
        f"Server: {server['name']}",
    ]
    if server.get("description"):
        header.append(server["description"])
    header.append("=" * 78)

    lines: list[str] = [comment_block(header), ""]

    # Interface
    lines.append("[Interface]")
    lines.append(f"Address = {server['address_v4']}")
    lines.append(f"ListenPort = {int(server['port'])}")
    lines.append(f"PrivateKey = {server_priv}")
    for extra in safe_list(server.get("interface_extras")):
        extra_line = str(extra).strip()
        if extra_line:
            lines.append(extra_line)
    lines.append("")

    # Peers
    for p in peers:
        peer_header = [
            "-" * 78,
            f"Peer: {p['name']}",
        ]
        if p.get("description"):
            peer_header.append(p["description"])
        peer_header.append("-" * 78)

        lines.append(comment_block(peer_header))
        lines.append("[Peer]")
        lines.append(f"PublicKey = {p['public_key']}")
        lines.append(f"PresharedKey = {p['preshared_key']}")
        lines.append("AllowedIPs = " + ", ".join(p["allowed_ips"]))
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def render_client_conf(server: dict, server_pub: str, p: dict) -> str:
    """
    Render client-side WireGuard config:
      - [Interface] includes peer private key, peer Address(/32), optional DNS
      - [Peer] includes server public key, PSK, Endpoint, AllowedIPs (client routing)

    client_routes semantics:
      - This is the routing table on the client.
      - If peer overrides it -> peer value wins
      - Else server default -> server value wins
      - Else fallback -> full-tunnel (0.0.0.0/0, ::/0)
    """
    client_allowed = p["client_allowed_ips"]

    dns = p.get("dns") or server.get("dns") or None

    header = [
        "=" * 78,
        f"Client: {p['name']}",
        f"Server: {server['name']}",
    ]
    if p.get("description"):
        header.append(p["description"])
    header.append("=" * 78)

    lines: list[str] = [comment_block(header), ""]

    # Interface
    lines.append("[Interface]")
    lines.append(f"PrivateKey = {p['private_key']}")
    lines.append(f"Address = {p['address']}/32")

    if dns:
        dns_list = safe_list(dns)
        if dns_list:
            lines.append("DNS = " + ", ".join(dns_list))
    for extra in p.get("interface_extras", []):
        extra_line = str(extra).strip()
        if extra_line:
            lines.append(extra_line)
    lines.append("")

    # Peer (server)
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_pub}")
    lines.append(f"PresharedKey = {p['preshared_key']}")
    lines.append(f"Endpoint = {server['endpoint']}:{int(server['port'])}")
    lines.append("AllowedIPs = " + ", ".join(map(str, client_allowed)))
    lines.append("PersistentKeepalive = 25")
    lines.append("")

    return "\n".join(lines).strip() + "\n"


# -----------------------------------------------------------------------------
# Main flow
# -----------------------------------------------------------------------------
def main() -> None:
    """
    Pipeline:
      1) Load YAML
      2) For each server:
          - ensure server keys exist
          - ensure each peer keys exist
          - build enriched in-memory model (with keys + computed defaults)
          - write server config + all client configs
    """
    cfg = load_cfg()
    ensure_dir(SECRETS, DIR_MODE)
    ensure_dir(OUT, DIR_MODE)

    for s in cfg["servers"]:
        # ---- Validate server mandatory fields
        sname = normalize_name(s.get("name", ""))
        s["name"] = sname  # keep normalized name inside object

        if not s.get("endpoint") or not s.get("port") or not s.get("address_v4"):
            raise SystemExit(f"server {sname}: missing endpoint/port/address_v4")

        peers_in = s.get("peers") or []
        if not isinstance(peers_in, list):
            raise SystemExit(f"server {sname}: peers must be a list")

        # ---- Server keys (persisted)
        sdir = SECRETS / sname
        spriv_p = sdir / "server_privatekey"
        spub_p = sdir / "server_publickey"

        if not spriv_p.exists():
            spriv = wg_genkey()
            write_secret(spriv_p, spriv)
        else:
            spriv = read_secret(spriv_p)

        if not spub_p.exists():
            spub = wg_pubkey(spriv)
            write_secret(spub_p, spub)
        else:
            spub = read_secret(spub_p)

        # ---- Peers: ensure keys + build enriched model
        enriched_peers: list[dict] = []

        for p in peers_in:
            pname = normalize_name(p.get("name", ""))
            if not p.get("address"):
                raise SystemExit(f"server {sname} peer {pname}: missing address")

            peer_ip = str(p["address"]).split("/")[0].strip()

            pdir = SECRETS / sname / "peers" / pname
            ppriv_p = pdir / "privatekey"
            ppub_p = pdir / "publickey"
            ppsk_p = pdir / "presharedkey"

            if not ppriv_p.exists():
                ppriv = wg_genkey()
                write_secret(ppriv_p, ppriv)
            else:
                ppriv = read_secret(ppriv_p)

            if not ppub_p.exists():
                ppub = wg_pubkey(ppriv)
                write_secret(ppub_p, ppub)
            else:
                ppub = read_secret(ppub_p)

            if not ppsk_p.exists():
                ppsk = wg_genpsk()
                write_secret(ppsk_p, ppsk)
            else:
                ppsk = read_secret(ppsk_p)

            allowed_list = resolve_peer_allowed(s, p, peer_ip)
            client_routes = resolve_client_allowed(s, p)

            enriched_peers.append(
                {
                    "name": pname,
                    "description": p.get("description"),
                    "address": peer_ip,
                    "allowed_ips": allowed_list,
                    "private_key": ppriv,
                    "public_key": ppub,
                    "preshared_key": ppsk,
                    # Client-side routing/DNS overrides (optional)
                    "client_allowed_ips": client_routes,
                    "dns": p.get("dns"),
                    "interface_extras": safe_list(p.get("interface_extras")),
                }
            )

        # ---- Write outputs
        out_sdir = OUT / sname
        out_pdir = out_sdir / "peers"
        ensure_dir(out_pdir, DIR_MODE)

        server_conf_path = out_sdir / f"{sname}.conf"
        server_conf_path.write_text(
            render_server_conf(s, spriv, enriched_peers),
            encoding="utf-8",
        )
        os.chmod(server_conf_path, FILE_MODE)

        for p in enriched_peers:
            client_conf_path = out_pdir / f"{p['name']}.conf"
            client_conf_path.write_text(
                render_client_conf(s, spub, p),
                encoding="utf-8",
            )
            os.chmod(client_conf_path, FILE_MODE)


if __name__ == "__main__":
    main()
