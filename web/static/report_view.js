// Report view page JavaScript

document.addEventListener('DOMContentLoaded', () => {
    loadReport();
});

function loadReport() {
    const report = getReportFromStorage(reportId);
    
    if (!report) {
        document.getElementById('report-subtitle').textContent = 'Report not found';
        document.getElementById('stats-container').innerHTML = '<div class="error">Report not found</div>';
        return;
    }
    
    const date = report.generated_at || report.saved_at;
    const mode = report.mode || 'all';
    const path = report.path || 'N/A';
    
    document.getElementById('report-subtitle').textContent = `${mode.toUpperCase()} scan · ${path} · ${formatDate(date)}`;
    document.getElementById('report-title').textContent = `Report ${reportId.substring(0, 12)}`;
    
    displayResults(report);
}

function downloadReport() {
    const report = getReportFromStorage(reportId);
    if (!report) {
        alert('Report not found');
        return;
    }
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnscan-report-${reportId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
