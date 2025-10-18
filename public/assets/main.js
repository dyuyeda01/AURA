// public/assets/main.js
async function fetchJSON(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`Failed to fetch ${path}`);
  return res.json();
}

function riskColor(score) {
  if (score >= 90) return 'text-red-300';
  if (score >= 80) return 'text-orange-300';
  if (score >= 70) return 'text-yellow-300';
  return 'text-green-300';
}

function renderList(data) {
  const list = document.getElementById('top-list');
  list.innerHTML = '';
  data.forEach(item => {
    const card = document.createElement('div');
    card.className = 'card bg-gray-900 rounded-xl p-4 border border-gray-800';
    const detailId = `d-${item.cve.replaceAll(/[^a-zA-Z0-9]/g,'')}`;
    card.innerHTML = `
      <div class="flex items-start justify-between gap-3">
        <div>
          <h3 class="text-lg font-semibold text-cyan-400">${item.cve}</h3>
          <p class="text-sm text-gray-400">${item.vendor ?? ''} ${item.product ?? ''}</p>
        </div>
        <div class="text-right">
          <div class="text-xs text-gray-500">AURA Score</div>
          <div class="text-2xl font-bold ${riskColor(item.aura_score)}">${item.aura_score}</div>
        </div>
      </div>
      <p class="mt-2 text-sm text-gray-200">${item.summary}</p>

      <details class="mt-3 bg-gray-950/60 rounded p-3">
        <summary class="cursor-pointer text-sm text-cyan-300">Scoring breakdown</summary>
        <div class="grid grid-cols-2 gap-2 text-xs text-gray-300 mt-2">
          <div>CVSS: ${(item.cvss ?? 0).toFixed(1)} (w ${item.score_breakdown.cvss_weight})</div>
          <div>EPSS: ${(item.epss ?? 0).toFixed(2)} (w ${item.score_breakdown.epss_weight})</div>
          <div>KEV: ${item.kev ? 'Yes' : 'No'} (w ${item.score_breakdown.kev_weight})</div>
          <div>Exploit PoC: ${item.exploit_poc ? 'Yes' : 'No'} (w ${item.score_breakdown.exploit_weight})</div>
          <div>Trend: ${item.trend_mentions} (w ${item.score_breakdown.trend_weight})</div>
          <div>AI Context: ${(item.ai_context ?? 0).toFixed(2)} (w ${item.score_breakdown.ai_weight})</div>
        </div>
      </details>
    `;
    list.appendChild(card);
  });
}

async function loadToday() {
  try {
    const data = await fetchJSON('data/aura_scores.json');
    renderList(data);
  } catch (e) {
    console.error(e);
    document.getElementById('top-list').innerHTML = '<div class="text-sm text-red-300">Failed to load today\'s feed.</div>';
  }
}

async function loadByDate(dateStr) {
  if (!dateStr) return loadToday();
  try {
    const path = `../data/history/${dateStr}.json`;
    const data = await fetchJSON(path);
    renderList(data);
  } catch (e) {
    document.getElementById('top-list').innerHTML = '<div class="text-sm text-yellow-300">No snapshot for that date.</div>';
  }
}

document.getElementById('loadDateBtn')?.addEventListener('click', () => {
  const d = document.getElementById('datePicker').value;
  loadByDate(d);
});

// Initial load
loadToday();
