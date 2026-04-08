from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import List

import yaml
from pydantic import BaseModel, model_validator


class PortRange(BaseModel):
    start: int = 1
    end: int = 65535

    @model_validator(mode="after")
    def validate_range(self) -> "PortRange":
        if self.start < 1 or self.end > 65535 or self.start > self.end:
            raise ValueError("port_range must satisfy 1 <= start <= end <= 65535")
        return self


class IPSpec(BaseModel):
    descriptor: str
    spec: str

    def expand_hosts(self) -> List[str]:
        """Parse spec into a list of IP address strings."""
        s = self.spec.strip()

        # CIDR notation
        try:
            network = ipaddress.ip_network(s, strict=False)
            # hosts() excludes network/broadcast; for /32 it returns the single address
            hosts = list(network.hosts())
            if not hosts:
                hosts = [network.network_address]
            return [str(ip) for ip in hosts]
        except ValueError:
            pass

        # Range: "10.0.0.1-10.0.0.50" or short form "10.0.0.1-50"
        m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d+(?:\.\d+\.\d+\.\d+)?)$", s)
        if m:
            start_ip = ipaddress.IPv4Address(m.group(1))
            end_part = m.group(2)
            if "." not in end_part:
                base = str(start_ip).rsplit(".", 1)[0]
                end_ip = ipaddress.IPv4Address(f"{base}.{end_part}")
            else:
                end_ip = ipaddress.IPv4Address(end_part)
            if end_ip < start_ip:
                raise ValueError(f"Range end {end_ip} is before start {start_ip}")
            result = []
            current = int(start_ip)
            end = int(end_ip)
            while current <= end:
                result.append(str(ipaddress.IPv4Address(current)))
                current += 1
            return result

        # Single IP
        try:
            ipaddress.ip_address(s)
            return [s]
        except ValueError:
            raise ValueError(f"Cannot parse IP spec: '{s}'")


class Config(BaseModel):
    scan_interval: int = 3600
    max_workers: int = 500
    connect_timeout: float = 1.0
    tls_timeout: float = 3.0
    port_range: PortRange = PortRange()
    db_path: str = "/data/ssl_sd.db"
    specs: List[IPSpec] = []


def load_config(path: str = "/config/config.yaml") -> Config:
    p = Path(path)
    if not p.exists():
        return Config()
    with open(p) as f:
        data = yaml.safe_load(f) or {}
    return Config(**data)
