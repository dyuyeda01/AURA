async function renderList(data) {
  const list = document.getElementById("top-list");
  list.innerHTML = "";

  // 🕒 Update last updated timestamp using actual file Last-Modified header
  const updatedEl = document.getElementById("last-updated");
  if (updatedEl) {
    try {
      const res = await fetch(`${basePath}data/aura_scores.json`, { method: "HEAD", cache: "no-store" });
      const lastModified = res.headers.get("Last-Modified");
      if (lastModified) {
        const date = new Date(lastModified);
        const options = {
          year: "numeric",
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          timeZoneName: "short"
        };
        updatedEl.textContent = `Last updated: ${date.toLocaleString(undefined, options)}`;
      } else {
        // fallback if header not available
        const now = new Date();
        updatedEl.textContent = `Last updated: ${now.toLocaleString()}`;
      }
    } catch (e) {
      console.warn("⚠️ Failed to read Last-Modified header:", e);
    }
  }

  data.forEach((item) => {
    const card = document.createElement("div");
    card.className = "card bg-gray-900 rounded-xl p-4 border border-gray-800";

    // Prefer direct EDB exploit URL
    const primaryExploitUrl =
      item.exploit_urls && item.exploit_urls.length
        ? item.exploit_urls[0]
        : `https://www.exploit-db.com/search?q=${item.cve}`;

    const exploitCount =
      item.exploit_edb_ids && item.exploit_edb_ids.length
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
        ? `<span
            class="ml-1 text-blue-400 text-lg"
            title="AI-related context detected: ${(item.ai_breakdown?.matched?.high || [])
              .concat(item.ai_breakdown?.matched?.medium || [])
              .join(", ") || "AI keywords detected"}">
            🤖
          </span>`
        : "";

    // 🧠 Unified summary logic (only one)
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
                ? `
              <a
                href="${primaryExploitUrl}"
                class="text-xs bg-red-700/60 px-2 py-1 rounded text-red-100 hover:bg-red-700/80 focus:outline-none focus:ring-2 focus:ring-red-500"
                target="_blank"
                rel="noopener noreferrer"
                title="Exploit PoC — click to open"
              >
                Exploit PoC${exploitCount}
              </a>`
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

      <!-- 🧠 Single summary (prefers AI/business tone) -->
      <p class="mt-2 text-sm text-gray-200">${item.summary_ciso ? "💼 " : ""}${mainSummary}</p>

      ${
        // 📰 News article section
        item.news_article && item.news_article.url
          ? `
        <a href="${item.news_article.url}" target="_blank" rel="noopener noreferrer"
           class="block mt-2 text-xs text-cyan-300 hover:text-cyan-100 underline decoration-dotted"
           title="${item.news_article.source || "News"}">
          📰 ${item.news_article.title || "View related article"} (${item.news_article.source || "News"})
        </a>`
          : ""
      }

      <details class="mt-3 bg-gray-950/60 rounded p-3">
        <summary class="cursor-pointer text-sm text-cyan-300">Scoring breakdown</summary>
        <div class="grid grid-cols-2 gap-2 text-xs text-gray-300 mt-2">
          <div>CVSS: ${(item.cvss ?? 0).toFixed(1)} (w ${item.score_breakdown?.cvss_weight ?? "?"})</div>
          <div>EPSS: ${(item.epss ?? 0).toFixed(2)} (w ${item.score_breakdown?.epss_weight ?? "?"})</div>
          <div>KEV: ${item.kev ? "Yes" : "No"} (w ${item.score_breakdown?.kev_weight ?? "?"})</div>
          <div>Exploit PoC: ${item.exploit_poc ? "Yes" : "No"} (w ${item.score_breakdown?.exploit_weight ?? "?"})</div>
          <div>Trend: ${item.trend_mentions} (w ${item.score_breakdown?.trend_weight ?? "?"})</div>
          <div>AI Context: ${(item.ai_context ?? 0).toFixed(2)} (w ${item.score_breakdown?.ai_weight ?? "?"})</div>
        </div>

        ${
          item.ai_breakdown && Object.values(item.ai_breakdown.matched || {}).flat().length
            ? `
          <div class="mt-3">
            <div class="text-xs text-gray-400 mb-1">AI Keywords</div>
            <ul class="list-disc list-inside text-xs text-blue-300 space-y-1">
              ${Object.entries(item.ai_breakdown.matched)
                .map(([lvl, terms]) => (terms.length ? `<li>${lvl}: ${terms.join(", ")}</li>` : ""))
                .join("")}
            </ul>
          </div>`
            : ""
        }

        ${
          item.exploit_urls && item.exploit_urls.length
            ? `
          <div class="mt-3">
            <div class="text-xs text-gray-400 mb-1">Exploit references</div>
            <ul class="list-disc list-inside text-xs text-cyan-200 space-y-1">
              ${item.exploit_urls
                .map(
                  (u) => `
                <li>
                  <a class="underline hover:text-cyan-100 break-all" href="${u}" target="_blank" rel="noopener noreferrer">
                    ${u.replace("https://www.exploit-db.com/", "")}
                  </a>
                </li>`
                )
                .join("")}
            </ul>
          </div>`
            : ""
        }
      </details>
    `;

    list.appendChild(card);
  });
}
