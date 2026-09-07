import hashlib
import json
import os
import sqlite3
from typing import Any


class AnalysisCache:
    def __init__(self, directory="reports", analyzer_version="1.0.0"):
        os.makedirs(directory, exist_ok=True)
        self.path = os.path.join(directory, ".cerberus-cache.sqlite3")
        self.analyzer_version = analyzer_version
        self._initialize()

    def _connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def _initialize(self):
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS analysis_cache (
                    cache_key TEXT PRIMARY KEY,
                    filepath TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    modified_ns INTEGER NOT NULL,
                    result_json TEXT NOT NULL
                )
            """)

    def _key(self, filepath, config):
        stat = os.stat(filepath)
        relevant = {
            key: value for key, value in config.items()
            if key not in {"event_callback", "quiet", "output_dir", "cache", "cache_enabled"}
            and not key.startswith("_")
        }
        payload = {
            "version": self.analyzer_version,
            "filepath": os.path.abspath(filepath),
            "size": stat.st_size,
            "modified_ns": stat.st_mtime_ns,
            "config": relevant,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(), stat

    def get(self, filepath, config):
        cache_key, stat = self._key(filepath, config)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM analysis_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        if not row:
            return None
        result = json.loads(row[0])
        result["cache_hit"] = True
        return result

    def put(self, filepath, config, result: dict[str, Any]):
        cache_key, stat = self._key(filepath, config)
        cached_result = dict(result)
        cached_result["cache_hit"] = False
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO analysis_cache
                (cache_key, filepath, file_size, modified_ns, result_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (cache_key, os.path.abspath(filepath), stat.st_size, stat.st_mtime_ns,
                 json.dumps(cached_result, ensure_ascii=False)),
            )
