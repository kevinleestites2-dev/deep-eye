#!/usr/bin/env python3
"""Build/rebuild the CVE RAG index from the local SQLite CVE database.

Usage:
    python scripts/build_cve_rag_index.py [--config config/config.yaml]
"""
import argparse
import sys
from pathlib import Path

# Make repo root importable
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from utils.config_loader import ConfigLoader
from modules.cve_intelligence.rag_index import CVERagIndex


def main():
    parser = argparse.ArgumentParser(description="Build CVE RAG index")
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Configuration file path",
    )
    parser.add_argument(
        "--cve-db",
        default="data/cve_intelligence.db",
        help="Path to CVE SQLite database",
    )
    args = parser.parse_args()

    try:
        config = ConfigLoader.load(args.config)
    except Exception as e:
        print(f"[!] Failed to load config: {e}", file=sys.stderr)
        config = {}

    rag = CVERagIndex(config)
    print(f"Building RAG index from {args.cve_db} ...")
    success = rag.build(args.cve_db, interactive=True)
    if not success:
        print("[!] Build failed (sklearn missing, DB missing, or empty)")
        sys.exit(1)

    rag.save()
    print(f"[+] Index saved to {rag.index_path}")
    print(f"[+] {len(rag._cve_meta)} CVEs indexed")


if __name__ == "__main__":
    main()
