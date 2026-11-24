"""Policy configuration, endpoint classification, and dev-agent allowlisting."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from oodatap.schemas import ActionEvent, DirectionClass, TlsBurstEvent

DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parent.parent.parent / "policies" / "default_policy.yaml"
)

PORT_PROTOCOL_MAP: dict[int, str] = {
    22: "ssh",
    53: "dns",
    80: "http",
    88: "kerberos",
    135: "msrpc",
    139: "netbios",
    389: "ldap",
    443: "https",
    445: "smb",
    636: "ldaps",
    1433: "mssql",
    2375: "docker",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5985: "winrm",
    5986: "winrm_tls",
    6443: "k8s_api",
    8080: "http_alt",
    8200: "vault",
    8443: "https_alt",
    9200: "elasticsearch",
    9418: "git",
}


class DevAllowlistConfig(BaseModel):
    """Destinations and hosts permitted for legitimate developer coding agents."""

    cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.0/8"])
    hosts: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=lambda: [3000, 5173, 8081, 9418])
    approved_dev_hosts: list[str] = Field(default_factory=list)


class ScoringWeights(BaseModel):
    """Relative contribution of each OodaTap detector."""

    sawtooth: float = 0.30
    coupler: float = 0.45
    kinematics: float = 0.25


class ScoringConfig(BaseModel):
    """Thresholds and timing parameters for the detection engine."""

    weights: ScoringWeights = Field(default_factory=ScoringWeights)
    alert_threshold: float = 0.58
    suspicious_threshold: float = 0.40
    min_turns_for_sawtooth: int = 4
    min_actions_for_coupling: int = 4
    max_obs_lag_seconds: float = 2.5
    max_dispatch_lag_seconds: float = 2.2
    fanout_window_seconds: float = 0.20


class PolicyConfig(BaseModel):
    """Complete OodaTap detection policy."""

    internal_cidrs: list[str] = Field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    )
    llm_domains: list[str] = Field(
        default_factory=lambda: [
            "api.openai.com",
            "api.anthropic.com",
            "generativelanguage.googleapis.com",
            "openrouter.ai",
            "api.groq.com",
            "api.together.xyz",
            "api.mistral.ai",
            "api.deepseek.com",
            "bedrock-runtime.",
            "openai.azure.com",
        ]
    )
    llm_ports: list[int] = Field(default_factory=lambda: [11434, 8000, 8080, 4000])
    sensitive_lateral_ports: list[int] = Field(
        default_factory=lambda: [
            22,
            88,
            135,
            139,
            389,
            445,
            636,
            1433,
            2375,
            3306,
            3389,
            5432,
            5985,
            5986,
            6443,
            8200,
            9200,
        ]
    )
    dev_allowlist: DevAllowlistConfig = Field(default_factory=DevAllowlistConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)

    def _parsed_networks(
        self, cidrs: list[str]
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in cidrs:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        return nets

    def is_internal_ip(self, ip: str) -> bool:
        """Return True if IP falls within configured RFC1918/internal ranges."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_loopback:
            return True
        return any(addr in net for net in self._parsed_networks(self.internal_cidrs))

    def is_dev_allowlisted_destination(self, dst_ip: str, dst_port: int) -> bool:
        """Return True if destination is an allowlisted developer target."""
        if dst_ip in self.dev_allowlist.hosts:
            return True
        try:
            addr = ipaddress.ip_address(dst_ip)
        except ValueError:
            return False
        if addr.is_loopback:
            return True
        if any(addr in net for net in self._parsed_networks(self.dev_allowlist.cidrs)):
            return True
        return dst_port in self.dev_allowlist.ports and self.is_internal_ip(dst_ip)

    def is_known_llm_endpoint(self, sni: str | None, dst_ip: str, dst_port: int) -> bool:
        """Check whether an SNI domain or self-hosted inference port matches known LLM endpoints."""
        if sni:
            lowered = sni.lower().strip(".")
            for pattern in self.llm_domains:
                pat = pattern.lower()
                if lowered == pat or lowered.endswith(f".{pat}") or pat in lowered:
                    return True
        return dst_port in self.llm_ports and self.is_internal_ip(dst_ip)

    def protocol_name(self, dst_port: int, fallback: str = "tcp") -> str:
        """Map well-known port numbers to readable protocol labels."""
        return PORT_PROTOCOL_MAP.get(dst_port, fallback)

    def classify_tls_burst(self, event: TlsBurstEvent) -> TlsBurstEvent:
        """Enrich a TLS burst event with LLM endpoint classification."""
        is_llm = event.is_llm_endpoint or self.is_known_llm_endpoint(
            event.sni, event.dst_ip, event.dst_port
        )
        if is_llm == event.is_llm_endpoint:
            return event
        return event.model_copy(update={"is_llm_endpoint": is_llm})

    def classify_action(self, event: ActionEvent) -> ActionEvent:
        """Enrich an action event with direction class, protocol label, and sensitivity flag."""
        proto = event.protocol
        if proto in {"tcp", "udp", ""} and event.dst_port:
            proto = self.protocol_name(event.dst_port, fallback=proto or "tcp")

        if self.is_dev_allowlisted_destination(event.dst_ip, event.dst_port):
            direction = DirectionClass.DEV_LOCAL
            sensitive = False
        elif self.is_internal_ip(event.dst_ip):
            direction = DirectionClass.EAST_WEST_INTERNAL
            sensitive = event.dst_port in self.sensitive_lateral_ports or proto in {
                "smb",
                "ldap",
                "ldaps",
                "ssh",
                "winrm",
                "winrm_tls",
                "rdp",
                "kerberos",
                "k8s_api",
                "vault",
                "postgres",
                "mysql",
                "mssql",
            }
        else:
            direction = DirectionClass.EXTERNAL_BENIGN
            sensitive = False

        return event.model_copy(
            update={
                "protocol": proto,
                "direction_class": direction,
                "is_sensitive_lateral": sensitive or event.is_sensitive_lateral,
            }
        )


def load_policy(path: Path | str | None = None) -> PolicyConfig:
    """Load policy YAML or fall back to repository default / built-in defaults."""
    target = Path(path) if path is not None else DEFAULT_POLICY_PATH
    if not target.exists():
        return PolicyConfig()
    raw: dict[str, Any] = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    return PolicyConfig.model_validate(raw)
