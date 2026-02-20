"""OSV API — https://osv.dev"""
import requests
from typing import List, Dict, Optional

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"


def query_package(name: str, version: str, ecosystem: str) -> List[Dict]:
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    try:
        resp = requests.post(OSV_QUERY_URL, json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json().get("vulns", [])
    except requests.RequestException:
        return []


def get_vuln_details(osv_id: str) -> Optional[Dict]:
    try:
        resp = requests.get(OSV_VULN_URL.format(osv_id), timeout=15)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return None


def extract_cve_ids(osv_vuln: Dict) -> List[str]:
    cves = [a for a in osv_vuln.get("aliases", []) if a.startswith("CVE-")]
    vuln_id = osv_vuln.get("id", "")
    if vuln_id.startswith("CVE-"):
        cves.append(vuln_id)
    return list(set(cves))


def extract_fixed_versions(osv_vuln: Dict) -> List[str]:
    fixed: List[str] = []
    for affected in osv_vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return list(set(fixed))


def extract_summary(osv_vuln: Dict) -> str:
    return osv_vuln.get("summary") or osv_vuln.get("details", "")[:300] or "No description available"
