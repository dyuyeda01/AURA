# scripts/prune_history.py
import os, datetime

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
HISTORY_DIR = os.path.join(BASE_DIR, "data", "history")

def prune(days=365):
    cutoff = datetime.date.today() - datetime.timedelta(days=days)
    for fname in os.listdir(HISTORY_DIR):
        if not fname.endswith(".json"): 
            continue
        try:
            d = datetime.datetime.strptime(fname.replace(".json",""), "%Y-%m-%d").date()
        except ValueError:
            continue
        if d < cutoff:
            os.remove(os.path.join(HISTORY_DIR, fname))
            print("Deleted:", fname)

if __name__ == "__main__":
    prune(365)
