import Levenshtein
import pybktree
from pathlib import Path

DB_DOMAIN = None
BK_TREE = None
BASE_DIR = Path(__file__).resolve().parent
WHITELIST_PATH = (BASE_DIR / ".." / "top-1m.csv").resolve()

def load_resources(top_domains_path=WHITELIST_PATH):
    """Load hanya sekali resource besar ke memory"""
    global DB_DOMAIN, BK_TREE

    if DB_DOMAIN is None:
        print("[INIT] Loading top-1m.csv...")
        with open(top_domains_path, 'r', encoding='utf-8') as f:
            DB_DOMAIN = {line.strip() for line in f if line.strip()}
        print(f"[INIT] Loaded {len(DB_DOMAIN)} domains")

        print("[INIT] Building BK-tree...")
        BK_TREE = pybktree.BKTree(Levenshtein.distance, DB_DOMAIN)
        print("[INIT] BK-tree ready")
