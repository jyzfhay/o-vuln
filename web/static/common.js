// Common utilities shared across pages

// Update active nav link
document.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.classList.remove('active');
        if ((path === '/' && link.id === 'nav-dashboard') ||
            (path === '/scan' && link.id === 'nav-scan') ||
            (path === '/reports' && link.id === 'nav-reports') ||
            (path === '/api/docs' && link.id === 'nav-api')) {
            link.classList.add('active');
        }
    });
});

// Storage key for reports
const STORAGE_KEY = 'vulnscan_reports';

// Generate unique ID
function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

// Save report to localStorage
function saveReportToStorage(reportData) {
    const reports = getReportsFromStorage();
    const reportId = reportData.id || generateId();
    const report = {
        id: reportId,
        ...reportData,
        saved_at: new Date().toISOString(),
    };
    reports[reportId] = report;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(reports));
    return reportId;
}

// Get all reports from localStorage
function getReportsFromStorage() {
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        return stored ? JSON.parse(stored) : {};
    } catch (e) {
        return {};
    }
}

// Get a specific report
function getReportFromStorage(reportId) {
    const reports = getReportsFromStorage();
    return reports[reportId] || null;
}

// Delete a report
function deleteReportFromStorage(reportId) {
    const reports = getReportsFromStorage();
    delete reports[reportId];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(reports));
}

// Clear all reports
function clearAllReportsFromStorage() {
    localStorage.removeItem(STORAGE_KEY);
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Format relative time
function formatRelativeTime(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return formatDate(dateString);
}

// Display scan results (shared function)
function displayResults(data, containerId = 'findings-container', statsContainerId = 'stats-container') {
    const statsContainer = document.getElementById(statsContainerId);
    const findingsContainer = document.getElementById(containerId);

    if (!statsContainer || !findingsContainer) return;

    // Display stats
    const severityCounts = data.severity_counts || {};
    const total = data.total_findings || 0;

    statsContainer.innerHTML = `
        <div class="stats-grid">
            <div class="stat-card total">
                <div class="label">Total Findings</div>
                <div class="value">${total}</div>
            </div>
            <div class="stat-card critical">
                <div class="label">Critical</div>
                <div class="value">${severityCounts.CRITICAL || 0}</div>
            </div>
            <div class="stat-card high">
                <div class="label">High</div>
                <div class="value">${severityCounts.HIGH || 0}</div>
            </div>
            <div class="stat-card medium">
                <div class="label">Medium</div>
                <div class="value">${severityCounts.MEDIUM || 0}</div>
            </div>
            <div class="stat-card low">
                <div class="label">Low</div>
                <div class="value">${severityCounts.LOW || 0}</div>
            </div>
            <div class="stat-card info">
                <div class="label">Info</div>
                <div class="value">${severityCounts.INFO || 0}</div>
            </div>
        </div>
    `;

    // Display findings
    const findings = data.findings || [];
    
    if (findings.length === 0) {
        findingsContainer.innerHTML = `
            <div class="empty-state">
                <h3>✓ No vulnerabilities found</h3>
                <p>Great job! No security issues detected.</p>
            </div>
        `;
        return;
    }

    const scannerIcons = {
        'dependency': '📦',
        'sast': '🔍',
        'network': '🌐',
    };

    findingsContainer.innerHTML = `
        <div class="findings-list">
            ${findings.map((finding, idx) => {
                const severity = finding.severity || 'UNKNOWN';
                const scanner = finding.scanner || 'unknown';
                const icon = scannerIcons[scanner] || '⚠️';
                const location = finding.location || 'N/A';
                const lineNumber = finding.line_number ? `:${finding.line_number}` : '';
                
                let cveRows = '';
                if (finding.cve_refs && finding.cve_refs.length > 0) {
                    cveRows = `
                        <div style="margin-top: 16px;">
                            <h4 style="font-size: 13px; color: var(--foreground-secondary); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">CVE References</h4>
                            <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                                <thead>
                                    <tr style="border-bottom: 1px solid var(--border);">
                                        <th style="text-align: left; padding: 8px; color: var(--muted-foreground); font-weight: 600;">CVE ID</th>
                                        <th style="text-align: left; padding: 8px; color: var(--muted-foreground); font-weight: 600;">CVSS</th>
                                        <th style="text-align: left; padding: 8px; color: var(--muted-foreground); font-weight: 600;">Severity</th>
                                        <th style="text-align: left; padding: 8px; color: var(--muted-foreground); font-weight: 600;">Links</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${finding.cve_refs.map(cve => {
                                        const score = cve.cvss_score ? cve.cvss_score.toFixed(1) : '—';
                                        const links = [];
                                        if (cve.nvd_url) links.push(`<a href="${cve.nvd_url}" target="_blank" style="color: var(--primary); text-decoration: none;">NVD</a>`);
                                        if (cve.mitre_url) links.push(`<a href="${cve.mitre_url}" target="_blank" style="color: var(--primary); text-decoration: none;">MITRE</a>`);
                                        return `
                                            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                                                <td style="padding: 8px; font-family: monospace;">${escapeHtml(cve.cve_id)}</td>
                                                <td style="padding: 8px;">${score}</td>
                                                <td style="padding: 8px;"><span class="badge ${cve.severity}">${cve.severity}</span></td>
                                                <td style="padding: 8px;">${links.join(' · ')}</td>
                                            </tr>
                                        `;
                                    }).join('')}
                                </tbody>
                            </table>
                        </div>
                    `;
                }

                const evidenceHtml = finding.evidence ? `
                    <div class="finding-evidence">${escapeHtml(finding.evidence)}</div>
                ` : '';

                const remediationHtml = finding.remediation ? `
                    <div class="finding-remediation">💡 ${escapeHtml(finding.remediation)}</div>
                ` : '';

                return `
                    <div class="finding-card" data-severity="${severity}" data-scanner="${scanner}">
                        <div class="finding-header" onclick="toggleFinding(${idx})">
                            <span class="badge ${severity}">${severity}</span>
                            <span class="scanner-badge">${icon} ${scanner}</span>
                            <span class="finding-title">${escapeHtml(finding.title || 'Unknown')}</span>
                            <span class="finding-location">${escapeHtml(location)}${escapeHtml(lineNumber)}</span>
                            <span class="expand-icon" id="icon-${idx}">▼</span>
                        </div>
                        <div class="finding-body" id="body-${idx}">
                            ${finding.description ? `<div class="finding-description">${escapeHtml(finding.description)}</div>` : ''}
                            ${evidenceHtml}
                            ${remediationHtml}
                            ${cveRows}
                        </div>
                    </div>
                `;
            }).join('')}
        </div>
    `;
}

function toggleFinding(idx) {
    const body = document.getElementById(`body-${idx}`);
    const icon = document.getElementById(`icon-${idx}`);
    const card = body.closest('.finding-card');
    
    body.classList.toggle('open');
    card.classList.toggle('open');
    icon.textContent = body.classList.contains('open') ? '▲' : '▼';
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
