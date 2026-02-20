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

// Generate unique ID (cryptographically secure)
function generateId() {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
        return crypto.randomUUID();
    }
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    }
    // Fallback when crypto unavailable (e.g. old env): timestamp-based only
    return Date.now().toString(36) + '-' + String(performance.now()).replace(/\D/g, '');
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

// Display scan results (shared function) — uses DOM to avoid innerHTML XSS
function displayResults(data, containerId = 'findings-container', statsContainerId = 'stats-container') {
    const statsContainer = document.getElementById(statsContainerId);
    const findingsContainer = document.getElementById(containerId);

    if (!statsContainer || !findingsContainer) return;

    const severityCounts = data.severity_counts || {};
    const total = data.total_findings || 0;

    // Build stats with DOM
    const statsGrid = document.createElement('div');
    statsGrid.className = 'stats-grid';
    const statCards = [
        ['total', 'Total Findings', total],
        ['critical', 'Critical', severityCounts.CRITICAL || 0],
        ['high', 'High', severityCounts.HIGH || 0],
        ['medium', 'Medium', severityCounts.MEDIUM || 0],
        ['low', 'Low', severityCounts.LOW || 0],
        ['info', 'Info', severityCounts.INFO || 0],
    ];
    statCards.forEach(([klass, label, value]) => {
        const card = document.createElement('div');
        card.className = 'stat-card ' + klass;
        const labelEl = document.createElement('div');
        labelEl.className = 'label';
        labelEl.textContent = label;
        const valueEl = document.createElement('div');
        valueEl.className = 'value';
        valueEl.textContent = String(value);
        card.appendChild(labelEl);
        card.appendChild(valueEl);
        statsGrid.appendChild(card);
    });
    statsContainer.replaceChildren(statsGrid);

    const findings = data.findings || [];
    const findingsList = document.createElement('div');
    findingsList.className = 'findings-list';

    if (findings.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        const h3 = document.createElement('h3');
        h3.textContent = '✓ No vulnerabilities found';
        const p = document.createElement('p');
        p.textContent = 'Great job! No security issues detected.';
        empty.appendChild(h3);
        empty.appendChild(p);
        findingsContainer.replaceChildren(empty);
        return;
    }

    const scannerIcons = { 'dependency': '📦', 'sast': '🔍', 'network': '🌐' };
    findings.forEach((finding, idx) => {
        const severity = finding.severity || 'UNKNOWN';
        const scanner = finding.scanner || 'unknown';
        const icon = scannerIcons[scanner] || '⚠️';
        const location = (finding.location || 'N/A') + (finding.line_number ? ':' + finding.line_number : '');

        const card = document.createElement('div');
        card.className = 'finding-card';
        card.dataset.severity = severity;
        card.dataset.scanner = scanner;

        const header = document.createElement('div');
        header.className = 'finding-header';
        header.onclick = () => toggleFinding(idx);

        const badge = document.createElement('span');
        badge.className = 'badge ' + severity;
        badge.textContent = severity;
        const scannerBadge = document.createElement('span');
        scannerBadge.className = 'scanner-badge';
        scannerBadge.textContent = icon + ' ' + scanner;
        const titleEl = document.createElement('span');
        titleEl.className = 'finding-title';
        titleEl.textContent = finding.title || 'Unknown';
        const locEl = document.createElement('span');
        locEl.className = 'finding-location';
        locEl.textContent = location;
        const expandIcon = document.createElement('span');
        expandIcon.className = 'expand-icon';
        expandIcon.id = 'icon-' + idx;
        expandIcon.textContent = '▼';

        header.append(badge, scannerBadge, titleEl, locEl, expandIcon);
        card.appendChild(header);

        const body = document.createElement('div');
        body.className = 'finding-body';
        body.id = 'body-' + idx;

        if (finding.description) {
            const desc = document.createElement('div');
            desc.className = 'finding-description';
            desc.textContent = finding.description;
            body.appendChild(desc);
        }
        if (finding.evidence) {
            const ev = document.createElement('div');
            ev.className = 'finding-evidence';
            ev.textContent = finding.evidence;
            body.appendChild(ev);
        }
        if (finding.remediation) {
            const rem = document.createElement('div');
            rem.className = 'finding-remediation';
            rem.textContent = '💡 ' + finding.remediation;
            body.appendChild(rem);
        }
        if (finding.cve_refs && finding.cve_refs.length > 0) {
            const cveDiv = document.createElement('div');
            cveDiv.style.marginTop = '16px';
            const cveH4 = document.createElement('h4');
            cveH4.textContent = 'CVE References';
            cveH4.style.fontSize = '13px';
            cveH4.style.marginBottom = '8px';
            cveDiv.appendChild(cveH4);
            const table = document.createElement('table');
            table.style.width = '100%';
            table.style.fontSize = '12px';
            const thead = document.createElement('thead');
            const headerRow = document.createElement('tr');
            ['CVE ID', 'CVSS', 'Severity', 'Links'].forEach(t => {
                const th = document.createElement('th');
                th.textContent = t;
                th.style.padding = '8px';
                headerRow.appendChild(th);
            });
            thead.appendChild(headerRow);
            table.appendChild(thead);
            const tbody = document.createElement('tbody');
            finding.cve_refs.forEach(cve => {
                const tr = document.createElement('tr');
                const tdId = document.createElement('td');
                tdId.textContent = cve.cve_id;
                tdId.style.fontFamily = 'monospace';
                const tdScore = document.createElement('td');
                tdScore.textContent = cve.cvss_score != null ? cve.cvss_score.toFixed(1) : '—';
                const tdSev = document.createElement('td');
                const sevBadge = document.createElement('span');
                sevBadge.className = 'badge ' + cve.severity;
                sevBadge.textContent = cve.severity;
                tdSev.appendChild(sevBadge);
                const tdLinks = document.createElement('td');
                if (cve.nvd_url) {
                    const a1 = document.createElement('a');
                    a1.href = cve.nvd_url;
                    a1.target = '_blank';
                    a1.rel = 'noopener noreferrer';
                    a1.textContent = 'NVD';
                    tdLinks.appendChild(a1);
                }
                if (cve.mitre_url) {
                    if (cve.nvd_url) tdLinks.appendChild(document.createTextNode(' · '));
                    const a2 = document.createElement('a');
                    a2.href = cve.mitre_url;
                    a2.target = '_blank';
                    a2.rel = 'noopener noreferrer';
                    a2.textContent = 'MITRE';
                    tdLinks.appendChild(a2);
                }
                tr.append(tdId, tdScore, tdSev, tdLinks);
                tbody.appendChild(tr);
            });
            table.appendChild(tbody);
            cveDiv.appendChild(table);
            body.appendChild(cveDiv);
        }
        card.appendChild(body);
        findingsList.appendChild(card);
    });
    findingsContainer.replaceChildren(findingsList);
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
