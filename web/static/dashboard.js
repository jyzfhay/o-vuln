// Dashboard page JavaScript

document.addEventListener('DOMContentLoaded', () => {
    loadDashboardStats();
    loadRecentScans();
});

function loadDashboardStats() {
    const reports = getReportsFromStorage();
    const reportList = Object.values(reports);
    
    let totalScans = reportList.length;
    let totalCritical = 0;
    let totalHigh = 0;
    let totalMedium = 0;
    
    reportList.forEach(report => {
        const counts = report.severity_counts || {};
        totalCritical += counts.CRITICAL || 0;
        totalHigh += counts.HIGH || 0;
        totalMedium += counts.MEDIUM || 0;
    });
    
    document.getElementById('total-scans').textContent = totalScans;
    document.getElementById('total-critical').textContent = totalCritical;
    document.getElementById('total-high').textContent = totalHigh;
    document.getElementById('total-medium').textContent = totalMedium;
}

function loadRecentScans() {
    const reports = getReportsFromStorage();
    const reportList = Object.values(reports)
        .sort((a, b) => new Date(b.generated_at || b.saved_at) - new Date(a.generated_at || a.saved_at))
        .slice(0, 5);
    
    const container = document.getElementById('recent-scans-list');
    container.replaceChildren();

    if (reportList.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        const p = document.createElement('p');
        p.textContent = 'No scans yet. ';
        const a = document.createElement('a');
        a.href = '/scan';
        a.textContent = 'Run your first scan';
        p.appendChild(a);
        empty.appendChild(p);
        container.appendChild(empty);
        return;
    }

    reportList.forEach(report => {
        const date = report.generated_at || report.saved_at;
        const counts = report.severity_counts || {};
        const total = report.total_findings || 0;
        const mode = report.mode || 'all';
        const item = document.createElement('div');
        item.className = 'scan-item';
        const header = document.createElement('div');
        header.className = 'scan-item-header';
        const left = document.createElement('div');
        const h3 = document.createElement('h3');
        const link = document.createElement('a');
        link.href = '/report/' + encodeURIComponent(report.id);
        link.textContent = 'Scan ' + report.id.substring(0, 8);
        h3.appendChild(link);
        const meta = document.createElement('p');
        meta.className = 'scan-meta';
        meta.textContent = mode.toUpperCase() + ' · ' + formatRelativeTime(date);
        left.appendChild(h3);
        left.appendChild(meta);
        const stats = document.createElement('div');
        stats.className = 'scan-stats-mini';
        const totalSpan = document.createElement('span');
        totalSpan.className = 'stat-mini total';
        totalSpan.textContent = String(total);
        stats.appendChild(totalSpan);
        if (counts.CRITICAL) {
            const s = document.createElement('span');
            s.className = 'stat-mini critical';
            s.textContent = String(counts.CRITICAL);
            stats.appendChild(s);
        }
        if (counts.HIGH) {
            const s = document.createElement('span');
            s.className = 'stat-mini high';
            s.textContent = String(counts.HIGH);
            stats.appendChild(s);
        }
        header.appendChild(left);
        header.appendChild(stats);
        item.appendChild(header);
        container.appendChild(item);
    });
}
