"""Parse Nmap XML output into a prioritized findings report.

Stdlib only. Reads Nmap XML (as produced by `nmap -oX`), ranks every
open port by risk, and renders a Markdown report and a console summary.
Diff mode compares two scans and lists new/gone hosts and ports.
"""

import argparse
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

# Risk score per service. Known-bad exposures score highest, well above
# anything a raw port count would suggest.
SERVICE_RISK = {
    "telnet": (100, "Telnet sends credentials in cleartext. Disable it and use SSH."),
    "netbios-ssn": (95, "SMB exposed: restrict to trusted hosts, disable SMBv1, patch."),
    "microsoft-ds": (95, "SMB exposed: restrict to trusted hosts, disable SMBv1, patch."),
    "ms-wbt-server": (90, "RDP exposed: put it behind a VPN/gateway, require MFA and NLA."),
    "ftp": (75, "FTP sends credentials in cleartext. Use SFTP/FTPS or remove it."),
    "snmp": (70, "SNMP exposed: restrict community strings, prefer SNMPv3 with auth."),
    "mysql": (70, "Database port exposed: bind to localhost or firewall it off."),
    "postgresql": (70, "Database port exposed: bind to localhost or firewall it off."),
    "mssql": (70, "Database port exposed: bind to localhost or firewall it off."),
    "vnc": (70, "VNC exposed: tunnel over SSH/VPN and require strong auth."),
    "http": (40, "Review the web service and its version for known issues."),
    "https": (30, "Confirm the TLS config and certificate are current."),
    "ssh": (25, "Confirm key-only auth and no default credentials."),
    "domain": (20, "Confirm this DNS service is intended to be public."),
}

DEFAULT_RISK = (15, "Confirm this service is intended to be reachable.")


def risk_for(service, port):
    """Return (score, remediation) for a service name/port."""
    if service in SERVICE_RISK:
        return SERVICE_RISK[service]
    if port == 23:
        return SERVICE_RISK["telnet"]
    if port in (139, 445):
        return SERVICE_RISK["microsoft-ds"]
    if port == 3389:
        return SERVICE_RISK["ms-wbt-server"]
    return DEFAULT_RISK


def tier(score):
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Info"


def parse_scan(path):
    """Parse an Nmap XML file. Returns {host_ip: [finding, ...]}.

    A finding is a dict: host, port, protocol, service, product, version,
    score, tier, remediation.
    """
    tree = ET.parse(path)
    hosts = {}
    for host_el in tree.getroot().iter("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")
        findings = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                service = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                port_num = int(port_el.get("portid"))
                score, remediation = risk_for(service, port_num)
                findings.append({
                    "host": ip, "port": port_num,
                    "protocol": port_el.get("protocol", "tcp"),
                    "service": service, "product": product, "version": version,
                    "score": score, "tier": tier(score), "remediation": remediation,
                })
        findings.sort(key=lambda f: -f["score"])
        hosts[ip] = findings
    return hosts


def render_markdown(hosts):
    lines = ["# Nmap findings report", ""]
    total = sum(len(v) for v in hosts.values())
    lines.append(f"Hosts scanned: {len(hosts)}  Open ports: {total}")
    lines.append("")
    for ip in sorted(hosts):
        findings = hosts[ip]
        lines.append(f"## {ip} ({len(findings)} open ports)")
        lines.append("")
        if not findings:
            lines.append("No open ports.")
            lines.append("")
            continue
        lines.append("| Port | Service | Risk | Remediation |")
        lines.append("| --- | --- | --- | --- |")
        for f in findings:
            svc = f["service"]
            if f["product"]:
                svc += f" ({f['product']} {f['version']})".rstrip()
            lines.append(f"| {f['port']}/{f['protocol']} | {svc} | "
                         f"{f['tier']} ({f['score']}) | {f['remediation']} |")
        lines.append("")
    return "\n".join(lines)


def render_console(hosts):
    lines = []
    for ip in sorted(hosts):
        lines.append(f"{ip}:")
        for f in hosts[ip]:
            lines.append(f"  {f['port']}/{f['protocol']} {f['service']} "
                         f"[{f['tier']} {f['score']}] - {f['remediation']}")
        if not hosts[ip]:
            lines.append("  no open ports")
    return "\n".join(lines)


def diff_scans(old, new):
    """Compare two parsed scans. Returns dict of new/gone hosts/ports."""
    old_hosts, new_hosts = set(old), set(new)
    result = {"new_hosts": sorted(new_hosts - old_hosts),
              "gone_hosts": sorted(old_hosts - new_hosts),
              "new_ports": [], "gone_ports": []}
    for ip in sorted(old_hosts & new_hosts):
        old_ports = {(f["port"], f["protocol"], f["service"]) for f in old[ip]}
        new_ports = {(f["port"], f["protocol"], f["service"]) for f in new[ip]}
        for p in sorted(new_ports - old_ports):
            result["new_ports"].append((ip,) + p)
        for p in sorted(old_ports - new_ports):
            result["gone_ports"].append((ip,) + p)
    return result


def render_diff(diff):
    lines = ["# Scan diff", ""]
    for key, label in (("new_hosts", "New hosts"), ("gone_hosts", "Gone hosts")):
        lines.append(f"## {label}")
        for item in diff[key]:
            lines.append(f"- {item}")
        if not diff[key]:
            lines.append("- none")
        lines.append("")
    for key, label in (("new_ports", "New ports"), ("gone_ports", "Gone ports")):
        lines.append(f"## {label}")
        for ip, port, proto, service in diff[key]:
            lines.append(f"- {ip} {port}/{proto} {service}")
        if not diff[key]:
            lines.append("- none")
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Turn Nmap XML into a prioritized findings report.")
    parser.add_argument("scan", help="Nmap XML file (-oX output)")
    parser.add_argument("--diff", metavar="OLD_XML",
                        help="compare against an older scan (scan = newer)")
    parser.add_argument("--markdown", action="store_true",
                        help="emit Markdown instead of console text")
    args = parser.parse_args(argv)
    try:
        hosts = parse_scan(args.scan)
    except (OSError, ET.ParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.diff:
        try:
            old = parse_scan(args.diff)
        except (OSError, ET.ParseError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(render_diff(diff_scans(old, hosts)))
        return 0
    print(render_markdown(hosts) if args.markdown else render_console(hosts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
