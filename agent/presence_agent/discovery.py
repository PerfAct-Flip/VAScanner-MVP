import ipaddress
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET

import psutil


# Virtual/container bridge interfaces (Docker, libvirt, VPN tunnels) aren't
# part of the customer's actual network — they're local to the agent's own
# host, and Docker's default /16 bridges are large enough to make a ping
# sweep of them alone blow past any reasonable discovery timeout.
_VIRTUAL_INTERFACE_PREFIXES = ("docker", "br-", "veth", "virbr", "tun", "tap")


def local_subnets() -> list[str]:
    """CIDRs for every active, non-loopback, non-virtual IPv4 interface.
    Wi-Fi and wired both show up here the same way, so discovery covers
    whichever link(s) happen to be up without needing to know or care which."""
    nets: set[str] = set()
    for iface_name, addrs in psutil.net_if_addrs().items():
        if iface_name.startswith(_VIRTUAL_INTERFACE_PREFIXES):
            continue
        for addr in addrs:
            if addr.family.name != "AF_INET" or not addr.netmask:
                continue
            if addr.address.startswith("127."):
                continue
            try:
                network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            except ValueError:
                continue
            if network.num_addresses > 4096:
                # A misconfigured netmask shouldn't turn into an hours-long sweep.
                continue
            nets.add(str(network))
    return sorted(nets)


def _resolve_nmap_binary(nmap_binary: str) -> str:
    return shutil.which(nmap_binary) or nmap_binary


def _run_nmap_sweep(exe: str, subnets: list[str], timeout: int, top_ports: int) -> list[dict]:
    """Runs a single discovery pass — host discovery (ARP for local subnets,
    same as a plain `-sn` sweep, which is what surfaces MAC addresses) plus
    a lightweight TCP scan of the most common ports, in one nmap invocation.
    Not a full port scan (that's what nuclei/the SSH audit are for) — just
    enough to flag what's actually reachable on each host, per the meeting
    note's "checks exposed ports" ask."""
    cmd = [exe, "-T4", "--top-ports", str(top_ports), "-oX", "-", *subnets]
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

        mac_el = host.find("address[@addrtype='mac']")
        mac_address = mac_el.get("addr") if mac_el is not None else None

        open_ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                if port_el.get("protocol") != "tcp":
                    continue
                state_el = port_el.find("state")
                portid = port_el.get("portid")
                if state_el is not None and state_el.get("state") == "open" and portid:
                    open_ports.append(int(portid))

        hosts.append(
            {
                "ip_address": address.get("addr"),
                "hostname": hostname,
                "mac_address": mac_address,
                "open_ports": sorted(open_ports),
            }
        )
    return hosts


def discover_hosts(
    nmap_binary: str,
    subnets: list[str],
    timeout: int,
    passes: int = 2,
    retry_delay_seconds: int = 15,
    top_ports: int = 50,
) -> list[dict]:
    """Sweeps the given CIDRs across multiple passes and returns the union
    of hosts that answered on any of them, each with the union of open
    ports seen across passes. A single pass misses hosts that were
    transiently unreachable — asleep, mid-reconnect, a dropped ARP reply —
    and would otherwise mark a device "not found" (or a port "closed") that
    simply didn't respond in time, so a second (or third) pass a bit later
    catches those without needing a whole extra manual scan."""
    if not subnets:
        return []

    exe = _resolve_nmap_binary(nmap_binary)
    hosts_by_ip: dict[str, dict] = {}
    errors: list[str] = []

    for attempt in range(1, passes + 1):
        try:
            found = _run_nmap_sweep(exe, subnets, timeout, top_ports)
        except Exception as exc:
            errors.append(str(exc))
        else:
            for host in found:
                existing = hosts_by_ip.get(host["ip_address"])
                if existing:
                    existing["hostname"] = existing["hostname"] or host["hostname"]
                    existing["mac_address"] = existing["mac_address"] or host["mac_address"]
                    existing["open_ports"] = sorted(set(existing["open_ports"]) | set(host["open_ports"]))
                else:
                    hosts_by_ip[host["ip_address"]] = host
        if attempt < passes:
            time.sleep(retry_delay_seconds)

    if not hosts_by_ip and errors:
        raise Exception(f"All {passes} discovery pass(es) failed; last error: {errors[-1]}")

    return list(hosts_by_ip.values())
