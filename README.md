# VulnScan

CVE-validated vulnerability scanner — **OSV · NVD · MITRE**

Scans dependencies, source code (SAST), and network targets. All findings are
enriched with CVSS scores, CVE IDs, NVD links, and MITRE CVE links.

## Install

```bash
cd vulnscan
pip install -r requirements.txt
```

## Usage

### Dependency scan (PyPI, npm, Cargo, Go, RubyGems…)
```bash
python vulnscan.py deps ./my-project
```

### SAST — static analysis
```bash
python vulnscan.py sast ./my-project --verbose
```

### Network scan *(only scan hosts you own / are authorized to test)*
```bash
python vulnscan.py net 192.168.1.1 --ports 22,80,443,3306,6379
python vulnscan.py net 10.0.0.0/24
```

### All-in-one
```bash
python vulnscan.py all ./my-project --net-targets 192.168.1.1
```

### Agent JSON mode (for automation / AI agents)
```bash
cat > /tmp/vulnscan-request.json <<'JSON'
{
  "scan": "all",
  "path": "./my-project",
  "net_targets": ["192.168.1.10"],
  "ports": [22, 80, 443],
  "tools": "auto",
  "timeout": 1.5
}
JSON

python vulnscan.py agent --request-file /tmp/vulnscan-request.json --output-file /tmp/vulnscan-response.json
cat /tmp/vulnscan-response.json
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--output` / `-o` | `./vulnscan-report` | Report output directory |
| `--format` / `-f` | `both` | `html`, `json`, or `both` |
| `--verbose` / `-v` | off | Show all findings in detail |
| `--ports` / `-p` | common | Comma-separated port list for network scan |
| `--timeout` / `-t` | `1.5` | Per-port TCP timeout (seconds) |
| `--no-banner` | off | Disable startup banner (useful for automation) |

Global options (like `--no-banner`) must be passed before the subcommand, e.g. `python vulnscan.py --no-banner deps .`.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | NVD API key — increases rate limit from 5 to 50 req/30s. Get one free at [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) |

## Data sources

| Source | What it provides |
|--------|-----------------|
| [OSV](https://osv.dev) | Package vulnerability database (PyPI, npm, crates.io, Go, RubyGems, Maven…) |
| [NVD API v2](https://nvd.nist.gov/developers/vulnerabilities) | CVSS scores, vectors, descriptions |
| [MITRE CVE](https://cveawg.mitre.org) | Authoritative CVE records + web links |

## SAST checks

Secrets · AWS keys · Private keys · Shell injection · SQL injection ·
Pickle deserialization · yaml.load · eval/exec · MD5/SHA-1 · Insecure random ·
Path traversal · XSS (innerHTML, dangerouslySetInnerHTML) · SSRF · XXE ·
Debug mode · Assert-for-auth · and more.

## Integrating with CI/CD

```bash
# Fail the build if any HIGH or CRITICAL findings exist
python vulnscan.py deps . --format json --output /tmp/vs
python - <<'EOF'
import json, sys
data = json.load(open("/tmp/vs/vulnscan-report.json"))
critical = sum(1 for f in data["findings"] if f["severity"] in ("CRITICAL","HIGH"))
sys.exit(1 if critical > 0 else 0)
EOF
```

Note: JSON reports are written even when there are zero findings.

## Legal

Only scan systems you own or have explicit written authorization to test.
Unauthorized scanning may be illegal.
