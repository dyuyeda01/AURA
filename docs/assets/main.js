// 🚀 Robust unified renderList — handles fetch, timestamp, safety, and rendering
async function renderList(data) {
  // 🧱 Validate and locate DOM
  const list = document.getElementById("top-list");
  const updatedEl = document.getElementById("last-updated");
  if (!list) {
    console.error("❌ Missing #top-list in DOM — cannot render.");
    return;
  }
  list.innerHTML = "";
  if (!Array.isArray(data)) {
    console.error("❌ renderList expected an array, got:", data);
    list.innerHTML = `<div class="p-4 text-sm text-red-300">No data to display. Check console.</div>`;
    return;
  }

  // 🕒 Update "Last updated" timestamp with multiple fallbacks
  if (updatedEl) {
    try {
      const res = await fetch(`${basePath}data/aura_scores.json`, { cache: "no-store" });
      let date = null;

      // Prefer header timestamp if available
      const lastModified = res.headers.get("Last-Modified");
      if (lastModified) {
        date = new Date(lastModified);
      } else {
        // Try JSON field timestamp fallback
        const json = await res.clone().json().catch(() => null);
        const ts =
          json?.last_run ||
          json?.meta?.last_run ||
          json?.generated_at ||
          json?.last_updated;
        if (ts) {
          date = new Date(ts);
        }
      }

      if (!date || isNaN(date.getTime())) date = new Date();
      const options = {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        timeZoneName: "short",
      };
      updatedEl.textContent = `Last updated: ${date.toLocaleString(undefined, options)}`;
    } catch (e) {
      console.warn("⚠️ Failed to fetch timestamp:", e);
      const now = new Date();
      updatedEl.textContent = `Last updated: ${now.toLocaleString()}`;
    }
  }

  // 🧩 Build cards for each entry
  data.forEach((item) => {
    const card = document.createElement("div");
    card.className = "card bg-gray-900 rounded-xl p-4 border border-gray-800";

    const primaryExploitUrl =
      item.exploit_urls?.[0] || `https://www.exploit-db.com/search?q=${item.cve}`;

    const exploitCount = item.exploit_edb_ids?.length
      ? ` (${item.exploit_edb_ids.length})`
      : "";

    // 🔥 Trend badge
    const trendBadge =
      item.trend_score > 0.3
        ? `<span title="Trending: ${item.trend_mentions} mentions" class="text-amber-400 text-lg ml-1">🔥</span>`
        : "";

    // 🤖 AI Context badge
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

    // 🧠 Main card content
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

    // Summary paragraph (use textContent for safety)
    const summaryEl = document.createElement("p");
    summaryEl.className = "mt-2 text-sm text-gray-200";
    summaryEl.textContent = `${item.summary_ciso ? "💼 " : ""}${mainSummary}`;
    card.appendChild(summaryEl);

    // 📰 News article section
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

    // 🔍 Details (scoring breakdown + AI keywords + exploits)
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

    // Append AI keywords if available
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

    // Append exploit URLs if available
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

  // 🟩 Render fallback if no data
  if (!data.length) {
    list.innerHTML = `<div class="p-4 text-sm text-yellow-300">No CVEs available at this time.</div>`;
  }
}
