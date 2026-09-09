import hashlib
import json
import os
import sqlite3
import threading
from typing import Any


IOC_FINGERPRINT_FILES = ("blacklist.txt", "suspect_strings.txt")


class AnalysisCache:
    def __init__(self, directory="reports", analyzer_version="1.0.0"):
        os.makedirs(directory, exist_ok=True)
        self.path = os.path.join(directory, ".cerberus-cache.sqlite3")
        self.analyzer_version = analyzer_version
        self._local = threading.local()
        self._connections = set()
        self._connections_lock = threading.Lock()
        self._ioc_memo_key = None
        self._ioc_memo_value = None
        self._initialize()

    def _connect(self):
        conn = getattr(self._local, "connection", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-8192")
            self._local.connection = conn
            with self._connections_lock:
                self._connections.add(conn)
        return conn

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

    @staticmethod
    def _ioc_files_state():
        state = []
        for name in IOC_FINGERPRINT_FILES:
            path = os.path.join("iocs", name)
            try:
                stat = os.stat(path)
                state.append((name, stat.st_mtime_ns, stat.st_size))
            except OSError:
                state.append((name, 0, -1))
        return tuple(state)

    def _ioc_content_fingerprint(self):
        current_state = self._ioc_files_state()
        if current_state != self._ioc_memo_key:
            digest = hashlib.sha256()
            for name, _, _ in current_state:
                digest.update(name.encode("utf-8"))
                path = os.path.join("iocs", name)
                try:
                    with open(path, "rb") as ioc_file:
                        digest.update(ioc_file.read())
                except OSError:
                    digest.update(b"missing")
            self._ioc_memo_key = current_state
            self._ioc_memo_value = digest.hexdigest()
        return self._ioc_memo_value

    def key_for(self, filepath, config):
        """Compute the cache key and file stat once, so get/put reuse them and
        avoid a second os.stat per file."""
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
            "ioc_fingerprint": self._ioc_content_fingerprint(),
            "config": relevant,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(), stat

    def get(self, filepath, config, cache_key=None):
        if cache_key is None:
            cache_key, _ = self.key_for(filepath, config)
        conn = self._connect()
        row = conn.execute(
            "SELECT result_json FROM analysis_cache WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()
        if not row:
            return None
        result = json.loads(row[0])
        result["cache_hit"] = True
        return result

    def put(self, filepath, config, result: dict[str, Any], cache_key=None, cache_stat=None):
        if cache_key is None or cache_stat is None:
            cache_key, cache_stat = self.key_for(filepath, config)
        cached_result = dict(result)
        cached_result["cache_hit"] = False
        conn = self._connect()
        conn.execute(
            """
            INSERT OR REPLACE INTO analysis_cache
            (cache_key, filepath, file_size, modified_ns, result_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (cache_key, os.path.abspath(filepath), cache_stat.st_size, cache_stat.st_mtime_ns,
             json.dumps(cached_result, ensure_ascii=False)),
        )
        conn.commit()

    def close(self):
        """Close every thread-local connection, including the ones created by
        batch worker threads, so the WAL file is released and checkpointed."""
        with self._connections_lock:
            connections = list(self._connections)
            self._connections.clear()
        for conn in connections:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        if hasattr(self._local, "connection"):
            self._local.connection = None
