import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET

import psutil


def local_subnets() -> list[str]:
    """CIDRs for every active, non-loopback IPv4 interface. Wi-Fi and wired
    both show up here the same way, so discovery covers whichever link(s)
    happen to be up without needing to know or care which."""
    nets: set[str] = set()
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family.name != "AF_INET" or not addr.netmask:
                continue
            if addr.address.startswith("127."):
                continue
            try:
                network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            except ValueError:
                continue
            if network.num_addresses > 65536:
                # A misconfigured netmask shouldn't turn into an hours-long sweep.
                continue
            nets.add(str(network))
    return sorted(nets)


def _resolve_nmap_binary(nmap_binary: str) -> str:
    return shutil.which(nmap_binary) or nmap_binary


def discover_hosts(nmap_binary: str, subnets: list[str], timeout: int) -> list[dict]:
    """Ping-sweeps the given CIDRs (`nmap -sn`) and returns the hosts that
    answered. Run as root when possible — nmap then uses ARP for local
    subnets, which is faster and more reliable than the ICMP/TCP fallback
    used otherwise."""
    if not subnets:
        return []

    exe = _resolve_nmap_binary(nmap_binary)
    cmd = [exe, "-sn", "-oX", "-", *subnets]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise Exception(f"nmap binary '{exe}' not found on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise Exception(f"nmap discovery timed out after {timeout}s.") from exc

    if result.returncode != 0:
        raise Exception(f"nmap exited {result.returncode}: {result.stderr[:500]}")

    hosts = []
    root = ET.fromstring(result.stdout)
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            continue

        hostname = None
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        hosts.append({"ip_address": address.get("addr"), "hostname": hostname})
    return hosts
