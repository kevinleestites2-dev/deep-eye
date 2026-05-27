"""Tests for CVE RAG index (Group F)."""
import os
import sqlite3
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

sklearn_available = True
try:
    import sklearn  # noqa: F401
except ImportError:
    sklearn_available = False

pytestmark = pytest.mark.skipif(not sklearn_available, reason="scikit-learn not installed")

from modules.cve_intelligence.rag_index import CVERagIndex


@pytest.fixture
def synthetic_cve_db(tmp_path):
    """Build a synthetic SQLite CVE DB with 3 CVEs."""
    db_path = tmp_path / "cve.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE cve_entries (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            severity TEXT,
            cvss_score REAL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE cve_technologies (
            id INTEGER PRIMARY KEY,
            cve_id TEXT,
            technology TEXT
        )
        """
    )

    rows = [
        ("CVE-2021-44228", "Apache Log4j2 JNDI injection allows remote code execution via crafted log messages", "critical", 10.0),
        ("CVE-2014-0160", "OpenSSL Heartbleed allows remote attackers to obtain sensitive information from process memory via TLS heartbeat", "high", 7.5),
        ("CVE-2017-5638", "Apache Struts2 remote code execution via Jakarta multipart parser content-type header", "critical", 10.0),
    ]
    cursor.executemany(
        "INSERT INTO cve_entries (cve_id, description, severity, cvss_score) VALUES (?, ?, ?, ?)",
        rows,
    )

    techs = [
        ("CVE-2021-44228", "log4j-core"),
        ("CVE-2014-0160", "openssl"),
        ("CVE-2017-5638", "struts2"),
    ]
    cursor.executemany(
        "INSERT INTO cve_technologies (cve_id, technology) VALUES (?, ?)", techs
    )
    conn.commit()
    conn.close()
    return str(db_path)


@pytest.fixture
def rag_config(tmp_path):
    return {
        "rag": {
            "index_path": str(tmp_path / "cve_rag.pkl"),
            "top_k": 5,
            "min_score": 0.05,
            "auto_rebuild": True,
        }
    }


class TestBuild:
    def test_build_from_synthetic(self, synthetic_cve_db, rag_config):
        rag = CVERagIndex(rag_config)
        success = rag.build(synthetic_cve_db, interactive=False)
        assert success
        assert rag.is_loaded()
        assert len(rag._cve_meta) == 3

    def test_build_missing_db(self, tmp_path, rag_config):
        rag = CVERagIndex(rag_config)
        result = rag.build(str(tmp_path / "nonexistent.db"), interactive=False)
        assert result is False
        assert not rag.is_loaded()

    def test_build_empty_db(self, tmp_path, rag_config):
        empty_db = tmp_path / "empty.db"
        conn = sqlite3.connect(str(empty_db))
        conn.execute("CREATE TABLE cve_entries (cve_id TEXT PRIMARY KEY, description TEXT, severity TEXT, cvss_score REAL)")
        conn.execute("CREATE TABLE cve_technologies (id INTEGER PRIMARY KEY, cve_id TEXT, technology TEXT)")
        conn.commit()
        conn.close()

        rag = CVERagIndex(rag_config)
        result = rag.build(str(empty_db), interactive=False)
        assert result is False


class TestSearch:
    def test_search_basic(self, synthetic_cve_db, rag_config):
        rag = CVERagIndex(rag_config)
        rag.build(synthetic_cve_db, interactive=False)

        hits = rag.search("log4j JNDI remote code execution")
        assert len(hits) > 0
        assert hits[0]["cve_id"] == "CVE-2021-44228"
        assert hits[0]["score"] > 0

    def test_search_struts(self, synthetic_cve_db, rag_config):
        rag = CVERagIndex(rag_config)
        rag.build(synthetic_cve_db, interactive=False)

        hits = rag.search("struts content-type RCE")
        assert any(h["cve_id"] == "CVE-2017-5638" for h in hits)

    def test_search_min_score(self, synthetic_cve_db, rag_config):
        rag_config["rag"]["min_score"] = 0.99
        rag = CVERagIndex(rag_config)
        rag.build(synthetic_cve_db, interactive=False)
        hits = rag.search("totally unrelated quantum gardening")
        assert hits == []

    def test_search_top_k(self, synthetic_cve_db, rag_config):
        rag_config["rag"]["min_score"] = 0.0
        rag = CVERagIndex(rag_config)
        rag.build(synthetic_cve_db, interactive=False)
        hits = rag.search("vulnerability", top_k=2)
        assert len(hits) <= 2

    def test_search_empty_query(self, synthetic_cve_db, rag_config):
        rag = CVERagIndex(rag_config)
        rag.build(synthetic_cve_db, interactive=False)
        assert rag.search("") == []
        assert rag.search("   ") == []

    def test_search_no_index(self, rag_config):
        rag = CVERagIndex(rag_config)
        assert rag.search("anything") == []


class TestPersistence:
    def test_save_and_load(self, synthetic_cve_db, rag_config):
        rag = CVERagIndex(rag_config)
        rag.build(synthetic_cve_db, interactive=False)
        rag.save()

        rag2 = CVERagIndex(rag_config)
        assert rag2.load()
        assert rag2.is_loaded()
        assert len(rag2._cve_meta) == 3

        hits = rag2.search("log4j JNDI")
        assert any(h["cve_id"] == "CVE-2021-44228" for h in hits)


class TestStaleness:
    def test_stale_when_index_missing(self, synthetic_cve_db, rag_config):
        rag = CVERagIndex(rag_config)
        assert rag.is_stale(synthetic_cve_db) is True

    def test_not_stale_after_build(self, synthetic_cve_db, rag_config):
        rag = CVERagIndex(rag_config)
        rag.build(synthetic_cve_db, interactive=False)
        rag.save()
        time.sleep(0.05)
        os.utime(rag.index_path, None)
        assert rag.is_stale(synthetic_cve_db) is False

    def test_stale_when_db_newer(self, synthetic_cve_db, rag_config):
        rag = CVERagIndex(rag_config)
        rag.build(synthetic_cve_db, interactive=False)
        rag.save()
        time.sleep(0.05)
        os.utime(synthetic_cve_db, None)
        assert rag.is_stale(synthetic_cve_db) is True
