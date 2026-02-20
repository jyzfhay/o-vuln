// VulnScan Scan Page JavaScript
// Note: displayResults, toggleFinding, escapeHtml, saveReportToStorage are imported from common.js

document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scan-form');
    const scanTypeSelect = document.getElementById('scan-type');
    const networkTargetsGroup = document.getElementById('network-targets-group');
    const netTargetsGroup = document.getElementById('net-targets-group');
    const portsGroup = document.getElementById('ports-group');
    const scanBtn = document.getElementById('scan-btn');
    const resultsPanel = document.getElementById('results-panel');

    function updateScanTypeFields() {
        const scanType = scanTypeSelect.value;
        
        if (scanType === 'net') {
            networkTargetsGroup.style.display = 'block';
            netTargetsGroup.style.display = 'none';
            portsGroup.style.display = 'block';
            document.getElementById('path').required = false;
            document.getElementById('targets').required = true;
        } else if (scanType === 'all') {
            networkTargetsGroup.style.display = 'none';
            netTargetsGroup.style.display = 'block';
            portsGroup.style.display = 'block';
            document.getElementById('path').required = true;
            document.getElementById('targets').required = false;
        } else {
            networkTargetsGroup.style.display = 'none';
            netTargetsGroup.style.display = 'none';
            portsGroup.style.display = 'none';
            document.getElementById('path').required = true;
            document.getElementById('targets').required = false;
        }
    }

    // Show/hide network-related fields based on scan type
    scanTypeSelect.addEventListener('change', updateScanTypeFields);
    // Run on load so "All" shows net-targets and ports without reselecting
    updateScanTypeFields();

    // Handle form submission
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(scanForm);
        const scanType = formData.get('scan');
        
        // Resolve tools: if any specific tool checkboxes are checked, use comma-separated list; else use dropdown
        const toolCheckboxes = scanForm.querySelectorAll('input[name^="tool-"]:checked');
        const toolsValue = toolCheckboxes.length > 0
            ? Array.from(toolCheckboxes).map(cb => cb.value).join(',')
            : (formData.get('tools') || 'auto');

        // Build request payload
        const payload = {
            scan: scanType,
            path: formData.get('path') || '.',
            tools: toolsValue,
            timeout: parseFloat(formData.get('timeout')) || 1.5,
        };

        // Handle network targets
        if (scanType === 'net') {
            const targets = formData.get('targets');
            if (!targets) {
                alert('Network targets are required for network scans');
                return;
            }
            payload.targets = targets.split(',').map(t => t.trim()).filter(t => t);
            const ports = formData.get('ports');
            if (ports) {
                payload.ports = ports;
            }
        } else if (scanType === 'all') {
            const netTargets = formData.get('net-targets');
            if (netTargets) {
                payload.net_targets = netTargets.split(',').map(t => t.trim()).filter(t => t);
                const ports = formData.get('ports');
                if (ports) {
                    payload.ports = ports;
                }
            }
        }

        // Disable button and show loading
        scanBtn.disabled = true;
        scanBtn.querySelector('.btn-text').style.display = 'none';
        scanBtn.querySelector('.btn-spinner').style.display = 'inline';

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Scan failed');
            }

            // Display results using common function
            if (typeof displayResults === 'function') {
                displayResults(data);
            } else {
                console.error('common.js not loaded');
            }
            resultsPanel.style.display = 'block';
            resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
            
            // Store current scan data for saving
            window.currentScanData = data;

        } catch (error) {
            alert(`Error: ${error.message}`);
            console.error('Scan error:', error);
        } finally {
            // Re-enable button
            scanBtn.disabled = false;
            scanBtn.querySelector('.btn-text').style.display = 'inline';
            scanBtn.querySelector('.btn-spinner').style.display = 'none';
        }
    });
});

function clearResults() {
    document.getElementById('results-panel').style.display = 'none';
    const statsEl = document.getElementById('stats-container');
    const findingsEl = document.getElementById('findings-container');
    while (statsEl.firstChild) statsEl.removeChild(statsEl.firstChild);
    while (findingsEl.firstChild) findingsEl.removeChild(findingsEl.firstChild);
    window.currentScanData = null;
}

function saveReport() {
    if (!window.currentScanData) {
        alert('No scan results to save');
        return;
    }
    
    const reportId = saveReportToStorage(window.currentScanData);
    alert(`Report saved! ID: ${reportId}`);
    // Redirect to reports page
    window.location.href = '/reports';
}
