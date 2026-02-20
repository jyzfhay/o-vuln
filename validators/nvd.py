"""NVD API v2 — https://nvd.nist.gov"""
import os
import threading
import time
import requests
from typing import Optional, Dict, Tuple, List

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_WEB_URL = "https://nvd.nist.gov/vuln/detail/{}"

# 5 req/30s anonymous, 50 req/30s with NVD_API_KEY
_last_request_time: float = 0.0
_ANON_INTERVAL: float = 6.1
_KEY_INTERVAL: float = 0.6
_rate_lock = threading.Lock()


def _rate_limit() -> None:
    global _last_request_time
    with _rate_lock:
        interval = _KEY_INTERVAL if os.environ.get("NVD_API_KEY") else _ANON_INTERVAL
        elapsed = time.time() - _last_request_time
        if elapsed < interval:
            time.sleep(interval - elapsed)
        _last_request_time = time.time()


def get_cve(cve_id: str) -> Optional[Dict]:
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    _rate_limit()
    try:
        resp = requests.get(NVD_CVE_URL, params={"cveId": cve_id}, headers=headers, timeout=20)
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            time.sleep(30)
            resp = requests.get(NVD_CVE_URL, params={"cveId": cve_id}, headers=headers, timeout=20)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        return vulns[0]["cve"] if vulns else None
    except requests.RequestException:
        return None


def extract_cvss(cve_data: Dict) -> Tuple[Optional[float], Optional[str]]:
    metrics = cve_data.get("metrics", {})
    # Prefer v3.1 > v3.0 > v2
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            return m.get("baseScore"), m.get("vectorString")
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        m = metrics["cvssMetricV2"][0].get("cvssData", {})
        return m.get("baseScore"), m.get("vectorString")
    return None, None


def extract_description(cve_data: Dict) -> str:
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def extract_published(cve_data: Dict) -> Optional[str]:
    pub = cve_data.get("published", "")
    return pub[:10] if pub else None


def extract_cwes(cve_data: Dict) -> List[str]:
    cwes: List[str] = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    return list(set(cwes))


def nvd_web_url(cve_id: str) -> str:
    return NVD_WEB_URL.format(cve_id)
