"""Network vulnerability scanner — TCP connect scan, banner grab, service analysis."""
import re
import socket
import ipaddress
import concurrent.futures
from typing import List, Tuple, Optional, Dict

from core.models import Finding, Severity

COMMON_PORTS: List[Tuple[int, str]] = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (389, "LDAP"), (443, "HTTPS"), (445, "SMB"), (1433, "MSSQL"),
    (1521, "Oracle"), (2375, "Docker-API"), (2376, "Docker-TLS"),
    (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"),
    (5672, "RabbitMQ"), (5900, "VNC"), (6379, "Redis"),
    (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (9200, "Elasticsearch"),
    (9300, "Elasticsearch-Cluster"), (10250, "Kubelet"),
    (11211, "Memcached"), (27017, "MongoDB"), (27018, "MongoDB"),
    (50070, "Hadoop-NameNode"),
]

DANGEROUS_SERVICES: Dict[int, Tuple[str, Severity, str, str]] = {
    23:    ("Telnet Service Exposed", Severity.CRITICAL,
            "Telnet transmits all data including credentials in plaintext",
            "Disable Telnet. Use SSH for remote access."),
    2375:  ("Unauthenticated Docker API Exposed", Severity.CRITICAL,
            "Unauthenticated Docker API allows full container and host takeover",
            "Disable TCP Docker socket or enable TLS client auth (--tlsverify)."),
    6379:  ("Redis Exposed Without Authentication", Severity.HIGH,
            "Redis without a password allows arbitrary data access and can lead to RCE via config rewrite",
            "Bind to 127.0.0.1, set requirepass, use firewall rules."),
    11211: ("Memcached Exposed", Severity.HIGH,
            "Exposed Memcached allows cache poisoning, data exfiltration, and DDoS amplification",
            "Bind Memcached to 127.0.0.1. Use SASL authentication."),
    27017: ("MongoDB Exposed Without Authentication", Severity.HIGH,
            "MongoDB without authentication allows unrestricted read/write to all databases",
            "Enable authentication, bind to localhost, use network segmentation."),
    27018: ("MongoDB (secondary) Exposed", Severity.HIGH,
            "MongoDB replica node exposed without authentication",
            "Enable authentication and restrict network access."),
    9200:  ("Elasticsearch Exposed", Severity.HIGH,
            "Elasticsearch without security enabled allows full index access and RCE",
            "Enable xpack.security.enabled: true and bind to localhost."),
    9300:  ("Elasticsearch Cluster Transport Exposed", Severity.HIGH,
            "Exposed transport layer can allow cluster hijacking",
            "Firewall port 9300. Enable TLS on transport layer."),
    10250: ("Kubelet API Exposed", Severity.CRITICAL,
            "Exposed Kubelet API allows container execution and full node compromise",
            "Restrict with --anonymous-auth=false and RBAC authorization."),
    50070: ("Hadoop NameNode Web UI Exposed", Severity.HIGH,
            "Exposed NameNode allows filesystem browsing and data exfiltration",
            "Restrict Hadoop management interfaces to trusted networks only."),
    5900:  ("VNC Remote Desktop Exposed", Severity.HIGH,
            "VNC exposure allows remote desktop access, often with weak authentication",
            "Tunnel VNC over SSH. Restrict access with firewall rules."),
    389:   ("LDAP Exposed (Plaintext)", Severity.MEDIUM,
            "LDAP on port 389 transmits directory queries and credentials in plaintext",
            "Use LDAPS (636) or STARTTLS."),
    445:   ("SMB Exposed", Severity.MEDIUM,
            "SMB exposure enables lateral movement and EternalBlue exploitation",
            "Block SMB at perimeter. Keep systems patched against MS17-010."),
    1433:  ("MSSQL Exposed", Severity.MEDIUM,
            "MSSQL exposed to the network — risk of brute-force and exploitation",
            "Restrict MSSQL access to application servers only."),
    1521:  ("Oracle DB Exposed", Severity.MEDIUM,
            "Oracle listener exposed — risk of brute-force and exploitation",
            "Restrict Oracle listener to trusted application servers only."),
    5672:  ("RabbitMQ AMQP Exposed", Severity.MEDIUM,
            "Exposed RabbitMQ may allow message injection or queue hijacking",
            "Restrict access. Change default credentials."),
}

PLAINTEXT_PROTOCOLS: Dict[int, Tuple[str, str]] = {
    21:  ("FTP transmits credentials in plaintext", "Use SFTP or FTPS instead"),
    23:  ("Telnet transmits all traffic in plaintext", "Use SSH instead"),
    80:  ("HTTP transmits data unencrypted", "Use HTTPS (port 443)"),
    110: ("POP3 transmits credentials in plaintext", "Use POP3S (995) or IMAPS"),
    143: ("IMAP transmits credentials in plaintext", "Use IMAPS (993)"),
    25:  ("SMTP without TLS transmits email in plaintext", "Enforce STARTTLS or SMTPS"),
    389: ("LDAP transmits directory queries in plaintext", "Use LDAPS (636) or STARTTLS"),
}

_HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
_PROBES: Dict[int, bytes] = {
    25: b"EHLO vulnscan\r\n",
    80: _HTTP_PROBE, 443: _HTTP_PROBE,
    8080: _HTTP_PROBE, 8443: _HTTP_PROBE,
    6379: b"INFO\r\n",
}

_VERSION_SIGNATURES = [
    (re.compile(r"SSH-2\.0-OpenSSH_([0-9]+\.[0-9]+[p0-9]*)"), "OpenSSH"),
    (re.compile(r"Server:\s*Apache/([0-9]+\.[0-9]+\.[0-9]+)"), "Apache httpd"),
    (re.compile(r"Server:\s*nginx/([0-9]+\.[0-9]+\.[0-9]+)"), "nginx"),
    (re.compile(r"220.*ProFTPD\s+([0-9]+\.[0-9]+\.[0-9]+)"), "ProFTPD"),
    (re.compile(r"220.*vsftpd\s+([0-9]+\.[0-9]+\.[0-9]+)"), "vsftpd"),
]


def scan(
    targets: List[str],
    ports: Optional[List[int]] = None,
    timeout: float = 1.5,
    progress_callback=None,
) -> List[Finding]:
    scan_ports = ports if ports is not None else [p for p, _ in COMMON_PORTS]
    port_names = dict(COMMON_PORTS)
    for p in scan_ports:
        port_names.setdefault(p, "Unknown")

    hosts: List[str] = []
    for target in targets:
        hosts.extend(_expand_target(target))
    hosts = list(dict.fromkeys(hosts))

    findings: List[Finding] = []
    for host in hosts:
        findings.extend(_scan_host(host, scan_ports, port_names, timeout))
        if progress_callback:
            progress_callback()
    return findings


def _expand_target(target: str) -> List[str]:
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = list(network.hosts())
        if hosts:
            return [str(h) for h in hosts[:256]]
        return [str(network.network_address)]
    except ValueError:
        return [target]


def _scan_host(host: str, ports: List[int], port_names: Dict[int, str], timeout: float) -> List[Finding]:
    open_ports: List[Tuple[int, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
        futures = {executor.submit(_probe_port, host, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            banner = future.result()
            if banner is not None:
                open_ports.append((port, banner))

    findings: List[Finding] = []
    for port, banner in sorted(open_ports):
        findings.extend(_analyze_port(host, port, port_names.get(port, "Unknown"), banner))
    return findings


def _probe_port(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            probe = _PROBES.get(port, b"")
            if probe:
                try:
                    sock.sendall(probe)
                except OSError:
                    pass
            try:
                return sock.recv(2048).decode("utf-8", errors="replace").strip()
            except (socket.timeout, OSError):
                return ""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def _analyze_port(host: str, port: int, service: str, banner: str) -> List[Finding]:
    location = f"{host}:{port}"

    if port in DANGEROUS_SERVICES:
        title, severity, description, remediation = DANGEROUS_SERVICES[port]
        return [Finding(
            title=f"{title} [{location}]",
            description=description,
            scanner="network",
            severity=severity,
            location=location,
            evidence=banner[:300] if banner else None,
            remediation=remediation,
        )]

    if port in PLAINTEXT_PROTOCOLS:
        desc, remediation = PLAINTEXT_PROTOCOLS[port]
        return [Finding(
            title=f"Plaintext Protocol — {service} [{location}]",
            description=desc,
            scanner="network",
            severity=Severity.MEDIUM,
            location=location,
            evidence=banner[:200] if banner else None,
            remediation=remediation,
        )]

    fingerprint = _fingerprint_banner(banner)
    if fingerprint:
        fingerprint.location = location
        return [fingerprint]

    return [Finding(
        title=f"Open Port — {port}/{service} [{host}]",
        description=f"Port {port} ({service}) is open.",
        scanner="network",
        severity=Severity.INFO,
        location=location,
        evidence=banner[:200] if banner else None,
    )]


def _fingerprint_banner(banner: str) -> Optional[Finding]:
    if not banner:
        return None
    for regex, product in _VERSION_SIGNATURES:
        m = regex.search(banner)
        if m:
            version = m.group(1)
            nvd_search = (
                f"https://nvd.nist.gov/vuln/search/results"
                f"?query={product}+{version}&results_type=overview"
            )
            return Finding(
                title=f"{product} {version} Fingerprinted",
                description=f"{product} {version} detected — verify no known CVEs apply.",
                scanner="network",
                severity=Severity.INFO,
                location="",
                evidence=banner[:200],
                remediation=f"Review NVD: {nvd_search}\nKeep {product} updated.",
            )
    return None
