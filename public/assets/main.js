// ============================
// 🌐 AURA Frontend Loader (Final)
// ============================

// Auto-detect base path for GitHub Pages (handles /AURA/ or root)
const basePath = (() => {
  const parts = window.location.pathname.split("/").filter(Boolean);
  const repo = parts.length > 0 ? parts[0] : "";
  const path = repo ? `/${repo}/` : "/";
  console.log(`[AURA] Using basePath: ${path}`);
  return path;
})();

// 🎨 Color helper for AURA risk score
function riskColor(score) {
  if (score >= 90) return "text-red-300";
  if (score >= 80) return "text-orange-300";
  if (score >= 70) return "text-yellow-300";
  return "text-green-300";
}

// 🚀 Robust unified renderList — handles fetch, timestamp, safety, and rendering
async function renderList() {
  const list = document.getElementById("top-list");
  const updatedEl = document.getElementById("last-updated");
  const analystEl = document.getElementById("analyst-prompt");
  const cisoEl = document.getElementById("ciso-prompt");

  if (!list) {
    console.error("❌ Missing #top-list in DOM — cannot render.");
    return;
  }

  // Temporary loading message
  list.innerHTML = `<div class="p-4 text-sm text-gray-400 italic">Loading AURA data...</div>`;

  try {
    const res = await fetch(`${basePath}data/aura_scores.json`, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    console.log("[AURA] JSON structure keys:", Object.keys(json));

    // ✅ FIX: Use json.cves[] from your live structure
    const data = Array.isArray(json)
      ? json
      : json.cves || json.top || json.items || json.results || [];

    console.log(`🧠 Loaded ${data.length} records from AURA feed`);

    // Populate daily summaries if available
    if (analystEl && json.daily_analyst_summary)
      analystEl.textContent = json.daily_analyst_summary;
    if (cisoEl && json.daily_ciso_summary)
      cisoEl.textContent = json.daily_ciso_summary;

    list.innerHTML = ""; // Clear loading text

    // 🕒 Update "Last updated" timestamp
    if (updatedEl) {
      const ts =
        json?.meta?.last_run || json?.last_run || json?.generated || json?.generated_at;
      const date = ts ? new Date(ts) : new Date();
      const options = {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        timeZoneName: "short",
      };
      updatedEl.textContent = `Last updated: ${date.toLocaleString(undefined, options)}`;
    }

    if (!data.length) {
      list.innerHTML = `<div class="p-4 text-sm text-yellow-300">No CVEs available at this time.</div>`;
      return;
    }

    // 🧩 Build cards
    data.forEach((item) => {
      const card = document.createElement("div");
      card.className = "card bg-gray-900 rounded-xl p-4 border border-gray-800";

      const primaryExploitUrl =
        item.exploit_urls?.[0] || `https://www.exploit-db.com/search?q=${item.cve}`;
      const exploitCount = item.exploit_edb_ids?.length
        ? ` (${item.exploit_edb_ids.length})`
        : "";

      const trendBadge =
        item.trend_score > 0.3
          ? `<span title="Trending: ${item.trend_mentions} mentions" class="text-amber-400 text-lg ml-1">🔥</span>`
          : "";

      const aiBadge =
        item.ai_context > 0.3
          ? `<span class="ml-1 text-blue-400 text-lg"
              title="AI-related context detected: ${(item.ai_breakdown?.matched?.high || [])
                .concat(item.ai_breakdown?.matched?.medium || [])
                .join(", ") || "AI keywords detected"}">🤖</span>`
          : "";

      const mainSummary =
        item.summary_ciso ||
        item.summary_analyst ||
        item.summary ||
        "No summary available.";

      card.innerHTML = `
        <div class="flex items-start justify-between gap-3">
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <h3 class="text-lg font-semibold text-cyan-400">${item.cve}</h3>
              ${trendBadge}
              ${aiBadge}
              ${
                item.exploit_poc
                  ? `<a href="${primaryExploitUrl}"
                       class="text-xs bg-red-700/60 px-2 py-1 rounded text-red-100 hover:bg-red-700/80 focus:outline-none focus:ring-2 focus:ring-red-500"
                       target="_blank" rel="noopener noreferrer"
                       title="Exploit PoC — click to open">
                       Exploit PoC${exploitCount}</a>`
                  : ""
              }
            </div>
            <p class="text-sm text-gray-400">${item.vendor ?? ""} ${item.product ?? ""}</p>
          </div>
          <div class="text-right">
            <div class="text-xs text-gray-500">AURA Score</div>
            <div class="text-2xl font-bold ${riskColor(item.aura_score)}">${item.aura_score}</div>
          </div>
        </div>
      `;

      const summaryEl = document.createElement("p");
      summaryEl.className = "mt-2 text-sm text-gray-200";
      summaryEl.textContent = `${item.summary_ciso ? "💼 " : ""}${mainSummary}`;
      card.appendChild(summaryEl);

      if (item.news_article?.url) {
        const link = document.createElement("a");
        link.href = item.news_article.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.title = item.news_article.source || "News";
        link.className =
          "block mt-2 text-xs text-cyan-300 hover:text-cyan-100 underline decoration-dotted";
        link.textContent = `📰 ${item.news_article.title || "View related article"} (${item.news_article.source || "News"})`;
        card.appendChild(link);
      }

      const details = document.createElement("details");
      details.className = "mt-3 bg-gray-950/60 rounded p-3";
      details.innerHTML = `
        <summary class="cursor-pointer text-sm text-cyan-300">Scoring breakdown</summary>
        <div class="grid grid-cols-2 gap-2 text-xs text-gray-300 mt-2">
          <div>CVSS: ${(item.cvss ?? 0).toFixed(1)} (w ${item.score_breakdown?.cvss_weight ?? "?"})</div>
          <div>EPSS: ${(item.epss ?? 0).toFixed(2)} (w ${item.score_breakdown?.epss_weight ?? "?"})</div>
          <div>KEV: ${item.kev ? "Yes" : "No"} (w ${item.score_breakdown?.kev_weight ?? "?"})</div>
          <div>Exploit PoC: ${item.exploit_poc ? "Yes" : "No"} (w ${item.score_breakdown?.exploit_weight ?? "?"})</div>
          <div>Trend: ${item.trend_mentions} (w ${item.score_breakdown?.trend_weight ?? "?"})</div>
          <div>AI Context: ${(item.ai_context ?? 0).toFixed(2)} (w ${item.score_breakdown?.ai_weight ?? "?"})</div>
        </div>
      `;

      if (item.ai_breakdown && Object.values(item.ai_breakdown.matched || {}).flat().length) {
        const aiDiv = document.createElement("div");
        aiDiv.className = "mt-3";
        aiDiv.innerHTML = `
          <div class="text-xs text-gray-400 mb-1">AI Keywords</div>
          <ul class="list-disc list-inside text-xs text-blue-300 space-y-1">
            ${Object.entries(item.ai_breakdown.matched)
              .map(([lvl, terms]) => (terms.length ? `<li>${lvl}: ${terms.join(", ")}</li>` : ""))
              .join("")}
          </ul>`;
        details.appendChild(aiDiv);
      }

      if (item.exploit_urls?.length) {
        const exDiv = document.createElement("div");
        exDiv.className = "mt-3";
        exDiv.innerHTML = `
          <div class="text-xs text-gray-400 mb-1">Exploit references</div>
          <ul class="list-disc list-inside text-xs text-cyan-200 space-y-1">
            ${item.exploit_urls
              .map(
                (u) =>
                  `<li><a class="underline hover:text-cyan-100 break-all" href="${u}" target="_blank" rel="noopener noreferrer">${u.replace(
                    "https://www.exploit-db.com/",
                    ""
                  )}</a></li>`
              )
              .join("")}
          </ul>`;
        details.appendChild(exDiv);
      }

      card.appendChild(details);
      list.appendChild(card);
    });
  } catch (err) {
    console.error("❌ Failed to load or render data:", err);
    list.innerHTML = `<div class="p-4 text-sm text-red-300">Failed to load AURA data. Check console.</div>`;
  }
}

// 🔄 Auto-run on DOM ready
document.addEventListener("DOMContentLoaded", renderList);
