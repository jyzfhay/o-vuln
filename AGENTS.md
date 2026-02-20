# VulnScan Agent Contract

This project provides a machine-friendly command for automation agents:

```bash
python vulnscan.py agent --request-file <request.json> --output-file <response.json>
```

`--request-file -` reads JSON from stdin.  
`--output-file -` writes JSON to stdout.

## Request schema

```json
{
  "scan": "deps|sast|net|all",
  "path": ".",
  "targets": ["host-or-cidr"],
  "net_targets": ["host-or-cidr"],
  "ports": "22,80,443",
  "timeout": 1.5,
  "tools": "auto|all|none|semgrep,bandit,trivy,nmap,nuclei"
}
```

Notes:
- Use `targets` for `scan: "net"`.
- Use `net_targets` for optional network scan when `scan: "all"`.
- `ports` can be a comma-separated string or an integer list.

## Response schema

```json
{
  "generated_at": "2026-02-20T16:00:00Z",
  "mode": "all",
  "path": ".",
  "targets": [],
  "tools_requested": "auto",
  "tools_enabled": ["trivy"],
  "timeout": 1.5,
  "total_findings": 0,
  "severity_counts": {},
  "findings": []
}
```

The `findings` array matches `vulnscan-report.json` entries.
