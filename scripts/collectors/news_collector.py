# scripts/collectors/news_collector.py
import feedparser

def count_mentions(cve, feeds):
    """Return how many RSS feed entries mention this CVE."""
    total = 0
    try:
        for url in feeds:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                text = (entry.get("title", "") + " " + entry.get("summary", "")).lower()
                if cve.lower() in text:
                    total += 1
    except Exception:
        pass
    return total
