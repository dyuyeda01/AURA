// public/assets/trends.js
async function fetchJSON(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`Failed to fetch ${path}`);
  return res.json();
}

async function loadMaster() {
  // ✅ Correct path (works locally + GitHub Pages)
  return await fetchJSON('data/aura_master.json');
}

// Filter history data for specific vendor or CVE
function filteredHistory(master, { vendor, cve }) {
  const points = [];
  Object.entries(master).forEach(([id, obj]) => {
    if (vendor && (obj.vendor || '').toLowerCase() !== vendor.toLowerCase()) return;
    if (cve && id !== cve) return;
    (obj.history || []).forEach(h =>
      points.push({ cve: id, date: h.date, score: h.score, vendor: obj.vendor || '' })
    );
  });
  points.sort((a, b) => a.date.localeCompare(b.date));
  return points;
}

// Convert history points into averaged daily series
function toSeries(points) {
  const byDate = {};
  points.forEach(p => {
    byDate[p.date] = byDate[p.date] || [];
    byDate[p.date].push(p.score);
  });
  const labels = Object.keys(byDate).sort();
  const avg = labels.map(d => {
    const arr = byDate[d];
    const s = arr.reduce((a, b) => a + b, 0);
    return Math.round((s / arr.length) * 10) / 10;
  });
  return { labels, avg };
}

// Count CVEs by vendor
function vendorCounts(master) {
  const counts = {};
  Object.values(master).forEach(obj => {
    const v = obj.vendor || 'Unknown';
    counts[v] = (counts[v] || 0) + 1;
  });
  const labels = Object.keys(counts);
  const data = labels.map(k => counts[k]);
  return { labels, data };
}

// Render dashboard charts
async function render() {
  const loadingEl = document.getElementById('loadingMessage');
  if (loadingEl) loadingEl.style.display = 'block';

  try {
    const master = await loadMaster();
    if (loadingEl) loadingEl.style.display = 'none';

    const vendorInput = document.getElementById('vendorFilter');
    const cveInput = document.getElementById('cveFilter');
    const applyBtn = document.getElementById('applyFilters');

    async function updateCharts() {
      const filt = { vendor: vendorInput.value.trim(), cve: cveInput.value.trim() };
      const points = filteredHistory(master, filt);
      const series = toSeries(points);
      const vc = vendorCounts(master);

      // Average score chart
      const ctx1 = document.getElementById('avgScoreChart').getContext('2d');
      if (window.avgChart) window.avgChart.destroy();
      window.avgChart = new Chart(ctx1, {
        type: 'line',
        data: {
          labels: series.labels,
          datasets: [{
            label: 'Average AURA Score',
            data: series.avg,
            borderColor: '#60a5fa',
            tension: 0.25
          }]
        },
        options: {
          plugins: { legend: { labels: { color: '#e5e7eb' } } },
          scales: {
            x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(148,163,184,0.2)' } },
            y: {
              ticks: { color: '#94a3b8' },
              grid: { color: 'rgba(148,163,184,0.2)' },
              suggestedMin: 0, suggestedMax: 100
            }
          }
        }
      });

      // Vendor count chart
      const ctx2 = document.getElementById('vendorCountChart').getContext('2d');
      if (window.vendorChart) window.vendorChart.destroy();
      window.vendorChart = new Chart(ctx2, {
        type: 'bar',
        data: {
          labels: vc.labels,
          datasets: [{
            label: 'CVE Count by Vendor',
            data: vc.data,
            backgroundColor: '#93c5fd'
          }]
        },
        options: {
          plugins: { legend: { labels: { color: '#e5e7eb' } } },
          scales: {
            x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(148,163,184,0.2)' } },
            y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(148,163,184,0.2)' }, suggestedMin: 0 }
          }
        }
      });
    }

    applyBtn.addEventListener('click', updateCharts);
    await updateCharts();

  } catch (err) {
    console.error(err);
    if (loadingEl) loadingEl.innerHTML = `<span style="color:#f87171;">⚠️ Failed to load trend data. Please try again later.</span>`;
  }
}

render();
