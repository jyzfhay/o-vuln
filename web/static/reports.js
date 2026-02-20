// Reports page JavaScript

document.addEventListener('DOMContentLoaded', () => {
    loadReports();
});

function loadReports() {
    const reports = getReportsFromStorage();
    const reportList = Object.values(reports)
        .sort((a, b) => new Date(b.generated_at || b.saved_at) - new Date(a.generated_at || a.saved_at));
    
    const container = document.getElementById('reports-list');
    
    if (reportList.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <h3>No reports yet</h3>
                <p>Run a scan to generate your first report.</p>
                <a href="/scan" class="btn-primary">Run Scan</a>
            </div>
        `;
        return;
    }
    
    container.innerHTML = reportList.map(report => {
        const date = report.generated_at || report.saved_at;
        const counts = report.severity_counts || {};
        const total = report.total_findings || 0;
        const mode = report.mode || 'all';
        const path = report.path || 'N/A';
        
        return `
            <div class="report-item">
                <div class="report-item-header">
                    <div>
                        <h3><a href="/report/${report.id}">${report.id.substring(0, 12)}</a></h3>
                        <p class="report-meta">
                            <span>${mode.toUpperCase()}</span>
                            <span>·</span>
                            <span>${path}</span>
                            <span>·</span>
                            <span>${formatDate(date)}</span>
                        </p>
                    </div>
                    <div class="report-actions">
                        <button class="btn-secondary" onclick="deleteReport('${report.id}')">Delete</button>
                    </div>
                </div>
                <div class="report-stats">
                    <div class="stat-mini total">Total: ${total}</div>
                    ${counts.CRITICAL ? `<div class="stat-mini critical">Critical: ${counts.CRITICAL}</div>` : ''}
                    ${counts.HIGH ? `<div class="stat-mini high">High: ${counts.HIGH}</div>` : ''}
                    ${counts.MEDIUM ? `<div class="stat-mini medium">Medium: ${counts.MEDIUM}</div>` : ''}
                    ${counts.LOW ? `<div class="stat-mini low">Low: ${counts.LOW}</div>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function deleteReport(reportId) {
    if (confirm('Are you sure you want to delete this report?')) {
        deleteReportFromStorage(reportId);
        loadReports();
    }
}

function clearAllReports() {
    if (confirm('Are you sure you want to delete all reports? This cannot be undone.')) {
        clearAllReportsFromStorage();
        loadReports();
    }
}
