# VulnScan Web Interface

A lightweight web interface for VulnScan that matches the TraKNC/SecurIQ brand guidelines with a professional security tool aesthetic.

## Features

- **Modern UI**: Dark theme matching TraKNC brand guidelines
- **Multiple Scan Types**: Support for dependency, SAST, network, and all-in-one scans
- **Real-time Results**: Interactive results display with expandable findings
- **CVE Integration**: Direct links to NVD and MITRE CVE databases
- **Responsive Design**: Works on desktop and mobile devices

## Installation

Install dependencies:

```bash
pip install -r ../requirements.txt
```

## Running the Web Interface

Start the Flask server:

```bash
cd web
python app.py
```

The interface will be available at `http://localhost:5000`

## Usage

1. **Select Scan Type**: Choose from Dependencies, SAST, Network, or All scans
2. **Configure Options**:
   - Set target path (for code scans)
   - Add network targets (for network scans)
   - Configure ports (for network scans)
   - Select tools (auto, all, or none)
   - Set timeout
3. **Run Scan**: Click "Run Scan" to execute
4. **View Results**: Results display with severity breakdown and detailed findings

## API Endpoints

### `POST /api/scan`
Execute a vulnerability scan.

**Request Body:**
```json
{
  "scan": "all|deps|sast|net",
  "path": ".",
  "targets": ["192.168.1.1"],
  "net_targets": ["192.168.1.1"],
  "ports": "22,80,443",
  "tools": "auto",
  "timeout": 1.5
}
```

**Response:**
```json
{
  "generated_at": "2026-02-20T16:00:00Z",
  "mode": "all",
  "total_findings": 5,
  "severity_counts": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 2
  },
  "findings": [...]
}
```

### `GET /api/health`
Health check endpoint.

## Brand Guidelines

The interface uses a professional security tool color scheme:

- **Background**: Deep dark blues (#0a0d14, #11141d)
- **Surfaces**: Dark blue-gray (#1a1f2e)
- **Accent**: Blue (#3b82f6)
- **Text**: Light grays (#e8ecf3, #a8b3c4)
- **Severity Colors**: Standard security severity palette

## Legal Notice

⚠️ Only scan systems you own or have explicit written authorization to test. Unauthorized scanning may be illegal.
