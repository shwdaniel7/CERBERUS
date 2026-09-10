"""Shared batch analysis runner.

Runs per-file analysis across separate processes so the CPU-bound analysis
engines (regex, string extraction) never starve the Tkinter mainloop: the GUI
process only coordinates futures instead of competing for the GIL with worker
threads. Falls back to threads automatically if process spawning is
unavailable in the environment.
"""

import os
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed


BATCH_ASSET_EXTENSIONS = {
    ".apng", ".avi", ".bmp", ".css", ".eot", ".flac", ".gif", ".ico",
    ".jpeg", ".jpg", ".m4a", ".mkv", ".mov", ".mp3", ".mp4", ".ogg",
    ".otf", ".png", ".scss", ".svg", ".tif", ".tiff", ".ttf", ".wav",
    ".webm", ".webp", ".woff", ".woff2",
}
BATCH_IGNORED_DIRECTORIES = {".git", ".venv", "__pycache__", "node_modules"}


def collect_candidates(folder_path):
    """Walk a folder and split its files into candidates and skipped assets."""
    files = []
    for root_path, directories, filenames in os.walk(folder_path):
        directories[:] = [
            directory for directory in directories
            if directory.lower() not in BATCH_IGNORED_DIRECTORIES
        ]
        files.extend(os.path.join(root_path, name) for name in filenames)
    files.sort()

    candidates = []
    skipped = []
    for filepath in files:
        extension = os.path.splitext(filepath)[1].lower()
        if extension in BATCH_ASSET_EXTENSIONS:
            skipped.append({
                "file": os.path.basename(filepath),
                "path": filepath,
                "reason": "asset extension excluded",
            })
        else:
            candidates.append(filepath)
    return candidates, skipped


def _clean_worker_config(config):
    """Return a shallow copy stripped of runtime-only keys so it can be
    pickled and shipped to worker processes."""
    cleaned = dict(config)
    for key in list(cleaned):
        if key.startswith("_"):
            cleaned.pop(key)
    cleaned.pop("event_callback", None)
    return cleaned


def _batch_analyze_file(filepath, config):
    """Top-level worker entry point. Must stay module-level and importable so
    Windows ``spawn`` can pickle it. Works both as a process and a thread
    worker."""
    from analyzer import analyze_file  # lazy import: avoids a circular import
    return analyze_file(filepath, config, show_details=False)


def _consume(futures, filepath_of, total, results, on_progress, on_error):
    for index, future in enumerate(as_completed(futures), start=1):
        filepath = filepath_of[future]
        try:
            result = future.result()
        except Exception as error:
            results.append({
                "file": os.path.basename(filepath),
                "path": filepath,
                "success": False,
                "error": str(error),
            })
            if on_error:
                on_error(filepath, str(error), index, total)
        else:
            results.append(result)
            if on_progress:
                on_progress(result, index, total)


def run_batch_analysis(folder_path, config, on_progress=None, on_error=None):
    """Analyze every candidate file in ``folder_path`` using worker processes.

    ``on_progress(result, index, total)`` and
    ``on_error(filepath, message, index, total)`` run in the calling thread as
    results arrive; they are never pickled. Returns
    ``(results, skipped, duration_seconds)``.
    """
    candidates, skipped = collect_candidates(folder_path)
    total = len(candidates)
    results = []
    if not total:
        return results, skipped, 0.0

    worker_config = _clean_worker_config(config)
    worker_count = max(1, min(int(config.get("workers", 1)), total))
    started = time.perf_counter()

    def consume_for(executor):
        futures = {
            executor.submit(_batch_analyze_file, filepath, worker_config): filepath
            for filepath in candidates
        }
        _consume(futures, futures, total, results, on_progress, on_error)
        return results

    try:
        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            consume_for(executor)
    except Exception:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            consume_for(executor)

    duration = round(time.perf_counter() - started, 3)
    return results, skipped, duration