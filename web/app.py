#!/usr/bin/env python3
"""Lightweight web interface for VulnScan."""
import json
import subprocess
import sys
from pathlib import Path
from flask import Flask, render_template, request, jsonify

app = Flask(__name__, static_folder='static', template_folder='templates')

# CORS is optional - only needed if serving frontend from different origin
try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    pass  # CORS not required for local development

# Get the project root directory
PROJECT_ROOT = Path(__file__).parent.parent
VULNSCAN_SCRIPT = PROJECT_ROOT / "vulnscan.py"


@app.route('/')
def index():
    """Serve the dashboard."""
    return render_template('dashboard.html')


@app.route('/scan')
def scan():
    """Serve the scan interface."""
    return render_template('scan.html')


@app.route('/reports')
def reports():
    """Serve the reports/history page."""
    return render_template('reports.html')


@app.route('/report/<report_id>')
def report_view(report_id):
    """Serve a specific report viewer."""
    return render_template('report_view.html', report_id=report_id)


@app.route('/api/docs')
def api_docs():
    """Serve the API documentation page."""
    return render_template('api_docs.html')


@app.route('/api/scan', methods=['POST'])
def run_scan():
    """Execute a vulnerability scan via the agent API."""
    try:
        data = request.get_json()
        
        # Validate required fields
        scan_type = data.get('scan', 'all')
        if scan_type not in ['deps', 'sast', 'net', 'all']:
            return jsonify({'error': 'Invalid scan type'}), 400
        
        # Build request payload
        request_payload = {
            'scan': scan_type,
            'path': data.get('path', '.'),
            'tools': data.get('tools', 'auto'),
            'timeout': data.get('timeout', 1.5),
        }
        
        # Handle network targets
        if scan_type == 'net':
            targets = data.get('targets', [])
            if not targets:
                return jsonify({'error': 'targets required for network scan'}), 400
            request_payload['targets'] = targets if isinstance(targets, list) else [targets]
            if data.get('ports'):
                request_payload['ports'] = data.get('ports')
        
        elif scan_type == 'all' and data.get('net_targets'):
            request_payload['net_targets'] = data.get('net_targets') if isinstance(data.get('net_targets'), list) else [data.get('net_targets')]
            if data.get('ports'):
                request_payload['ports'] = data.get('ports')
        
        # Execute vulnscan agent command
        cmd = [
            sys.executable,
            str(VULNSCAN_SCRIPT),
            'agent',
            '--request-file', '-',
            '--output-file', '-',
            '--no-banner',
        ]
        
        request_json = json.dumps(request_payload)
        result = subprocess.run(
            cmd,
            input=request_json,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
            cwd=str(PROJECT_ROOT),
        )
        
        if result.returncode != 0:
            return jsonify({
                'error': 'Scan failed',
                'stderr': result.stderr,
            }), 500
        
        # Parse response
        try:
            response_data = json.loads(result.stdout)
            return jsonify(response_data)
        except json.JSONDecodeError:
            return jsonify({
                'error': 'Invalid JSON response',
                'stdout': result.stdout[:500],
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'ok'})


@app.route('/api/reports', methods=['GET'])
def list_reports():
    """List all stored scan reports."""
    # For now, return empty list - can be extended with file-based storage
    return jsonify({'reports': []})


@app.route('/api/reports/<report_id>', methods=['GET'])
def get_report(report_id):
    """Get a specific scan report."""
    # For now, return 404 - can be extended with file-based storage
    return jsonify({'error': 'Report not found'}), 404


@app.route('/api/reports', methods=['POST'])
def save_report():
    """Save a scan report."""
    data = request.get_json()
    # For now, just return success - can be extended with file-based storage
    return jsonify({'status': 'saved', 'id': data.get('id', 'temp')})


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8080))  # Default to 8080
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() in ('1', 'true', 'yes')
    host = os.environ.get('BIND_ADDRESS', '127.0.0.1')  # Use 0.0.0.0 to allow remote access
    app.run(debug=debug, host=host, port=port)
