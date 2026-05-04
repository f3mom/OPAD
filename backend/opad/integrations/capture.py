from __future__ import annotations

import shlex
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class CapturePlan:
    provider: str
    interface: str
    listen: str
    bpf: str
    tcpdump_command: str
    pcap_broker_command: str
    docker_compose_service: dict[str, Any]
    consumers: list[str]


def build_bpf(exclude_ports: list[int] | None = None, include_cidrs: list[str] | None = None, extra: str | None = None) -> str:
    parts = []
    if include_cidrs:
        parts.append("(" + " or ".join(f"net {c}" for c in include_cidrs) + ")")
    for p in exclude_ports or []:
        parts.append(f"not port {int(p)}")
    if extra:
        parts.append(f"({extra})")
    return " and ".join(parts) if parts else "ip"


def pcap_broker_plan(cfg: dict[str, Any]) -> CapturePlan:
    cap = cfg.get("capture", {})
    scope = cfg.get("scope", {})
    interface = cap.get("interface", cfg.get("network", {}).get("game_interface", "eth0"))
    listen = cap.get("listen", "0.0.0.0:4242")
    bpf = build_bpf(cap.get("exclude_ports", []), cap.get("include_cidrs") or scope.get("allowed_cidrs"), cap.get("bpf_extra"))
    tcpdump = f"tcpdump -i {shlex.quote(interface)} -n --immediate-mode -s 65535 -U -w - {shlex.quote(bpf)}"
    broker = f"pcap-broker -listen {shlex.quote(listen)} -cmd {shlex.quote(tcpdump)}"
    docker_service = {
        "image": "ghcr.io/fox-it/pcap-broker:latest",
        "restart": "unless-stopped",
        "network_mode": "host",
        "cap_add": ["NET_RAW", "NET_ADMIN"],
        "environment": {
            "LISTEN_ADDRESS": listen,
            "PCAP_COMMAND": tcpdump,
        },
    }
    return CapturePlan(
        provider=cap.get("provider", "pcap_broker"),
        interface=interface,
        listen=listen,
        bpf=bpf,
        tcpdump_command=tcpdump,
        pcap_broker_command=broker,
        docker_compose_service=docker_service,
        consumers=["Packmate", "Tulip", "Pkappa2", "Shovel/Suricata", "Wireshark/tshark", "OPAD native"],
    )


def remote_ssh_capture_plan(host: str, user: str, interface: str, listen: str = "0.0.0.0:4242", ssh_port: int = 22) -> dict[str, Any]:
    bpf = f"not port {int(ssh_port)}"
    command = f"ssh {shlex.quote(user)}@{shlex.quote(host)} tcpdump -U --immediate-mode -ni {shlex.quote(interface)} -s 65535 -w - {shlex.quote(bpf)}"
    return {
        "listen": listen,
        "remote_host": host,
        "remote_user": user,
        "interface": interface,
        "pcap_command": command,
        "warning": "Exclude SSH port to avoid capturing the PCAP transport loop.",
    }
