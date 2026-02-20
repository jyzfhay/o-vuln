"""MITRE CVE API — https://cveawg.mitre.org"""
import requests
from typing import Optional, Dict, List

MITRE_CVE_API = "https://cveawg.mitre.org/api/cve/{}"
MITRE_CVE_WEB = "https://www.cve.org/CVERecord?id={}"


def cve_web_url(cve_id: str) -> str:
    return MITRE_CVE_WEB.format(cve_id)


def get_cve(cve_id: str) -> Optional[Dict]:
    try:
        resp = requests.get(MITRE_CVE_API.format(cve_id), timeout=15)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return None


def extract_description(data: Dict) -> str:
    try:
        for d in data["containers"]["cna"]["descriptions"]:
            if d.get("lang", "").startswith("en"):
                return d.get("value", "")
    except (KeyError, TypeError):
        pass
    return ""


def extract_published(data: Dict) -> Optional[str]:
    try:
        pub = data.get("cveMetadata", {}).get("datePublished", "")
        return pub[:10] if pub else None
    except (AttributeError, TypeError):
        return None


def extract_cwes(data: Dict) -> List[str]:
    """CWE IDs from CNA problem types, e.g. ['CWE-89']."""
    cwes: List[str] = []
    try:
        for pt in data["containers"]["cna"].get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId", "")
                if cwe_id.startswith("CWE-"):
                    cwes.append(cwe_id)
    except (KeyError, TypeError):
        pass
    return list(set(cwes))


def extract_affected(data: Dict) -> List[Dict]:
    try:
        return data["containers"]["cna"].get("affected", [])
    except (KeyError, TypeError):
        return []
