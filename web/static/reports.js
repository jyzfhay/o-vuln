// Reports page JavaScript

document.addEventListener('DOMContentLoaded', () => {
    loadReports();
});

function loadReports() {
    const reports = getReportsFromStorage();
    const reportList = Object.values(reports)
        .sort((a, b) => new Date(b.generated_at || b.saved_at) - new Date(a.generated_at || a.saved_at));
    
    const container = document.getElementById('reports-list');
    container.replaceChildren();

    if (reportList.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        const h3 = document.createElement('h3');
        h3.textContent = 'No reports yet';
        const p = document.createElement('p');
        p.textContent = 'Run a scan to generate your first report.';
        const a = document.createElement('a');
        a.href = '/scan';
        a.className = 'btn-primary';
        a.textContent = 'Run Scan';
        empty.appendChild(h3);
        empty.appendChild(p);
        empty.appendChild(a);
        container.appendChild(empty);
        return;
    }

    reportList.forEach(report => {
        const date = report.generated_at || report.saved_at;
        const counts = report.severity_counts || {};
        const total = report.total_findings || 0;
        const mode = report.mode || 'all';
        const path = report.path || 'N/A';
        const item = document.createElement('div');
        item.className = 'report-item';
        const header = document.createElement('div');
        header.className = 'report-item-header';
        const left = document.createElement('div');
        const h3 = document.createElement('h3');
        const link = document.createElement('a');
        link.href = '/report/' + encodeURIComponent(report.id);
        link.textContent = report.id.substring(0, 12);
        h3.appendChild(link);
        const meta = document.createElement('p');
        meta.className = 'report-meta';
        meta.textContent = mode.toUpperCase() + ' · ' + path + ' · ' + formatDate(date);
        left.appendChild(h3);
        left.appendChild(meta);
        const actions = document.createElement('div');
        actions.className = 'report-actions';
        const delBtn = document.createElement('button');
        delBtn.className = 'btn-secondary';
        delBtn.textContent = 'Delete';
        delBtn.onclick = () => deleteReport(report.id);
        actions.appendChild(delBtn);
        header.appendChild(left);
        header.appendChild(actions);
        item.appendChild(header);
        const stats = document.createElement('div');
        stats.className = 'report-stats';
        const totalDiv = document.createElement('div');
        totalDiv.className = 'stat-mini total';
        totalDiv.textContent = 'Total: ' + total;
        stats.appendChild(totalDiv);
        if (counts.CRITICAL) {
            const d = document.createElement('div');
            d.className = 'stat-mini critical';
            d.textContent = 'Critical: ' + counts.CRITICAL;
            stats.appendChild(d);
        }
        if (counts.HIGH) {
            const d = document.createElement('div');
            d.className = 'stat-mini high';
            d.textContent = 'High: ' + counts.HIGH;
            stats.appendChild(d);
        }
        if (counts.MEDIUM) {
            const d = document.createElement('div');
            d.className = 'stat-mini medium';
            d.textContent = 'Medium: ' + counts.MEDIUM;
            stats.appendChild(d);
        }
        if (counts.LOW) {
            const d = document.createElement('div');
            d.className = 'stat-mini low';
            d.textContent = 'Low: ' + counts.LOW;
            stats.appendChild(d);
        }
        item.appendChild(stats);
        container.appendChild(item);
    });
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
