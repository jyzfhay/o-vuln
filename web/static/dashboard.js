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
    
    if (reportList.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No scans yet. <a href="/scan">Run your first scan</a></p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = reportList.map(report => {
        const date = report.generated_at || report.saved_at;
        const counts = report.severity_counts || {};
        const total = report.total_findings || 0;
        const mode = report.mode || 'all';
        
        return `
            <div class="scan-item">
                <div class="scan-item-header">
                    <div>
                        <h3><a href="/report/${report.id}">Scan ${report.id.substring(0, 8)}</a></h3>
                        <p class="scan-meta">${mode.toUpperCase()} · ${formatRelativeTime(date)}</p>
                    </div>
                    <div class="scan-stats-mini">
                        <span class="stat-mini total">${total}</span>
                        ${counts.CRITICAL ? `<span class="stat-mini critical">${counts.CRITICAL}</span>` : ''}
                        ${counts.HIGH ? `<span class="stat-mini high">${counts.HIGH}</span>` : ''}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}
