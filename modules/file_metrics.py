import hashlib


CHUNK_SIZE = 1024 * 1024
MAX_BUFFERED_BYTES = 128 * 1024 * 1024


def collect_file_metrics(filepath):
    """Collect reusable byte metrics in one streaming pass."""
    digest = hashlib.sha256()
    byte_counts = [0] * 256
    file_size = 0

    with open(filepath, "rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
            file_size += len(chunk)
            for byte in chunk:
                byte_counts[byte] += 1

    return {
        "sha256": digest.hexdigest(),
        "byte_counts": byte_counts,
        "file_size": file_size,
    }


def read_analysis_buffer(filepath, max_buffered=MAX_BUFFERED_BYTES, compute_histogram=True):
    """Read a file once, returning the full byte content together with the
    streaming metrics so every analysis engine can share the same buffer
    instead of reopening the file multiple times.

    Returns a ``(content, metrics)`` tuple. ``content`` is ``None`` when the
    file is larger than ``max_buffered`` bytes; in that case callers should
    fall back to the per-engine reads to keep peak memory bounded. When
    ``compute_histogram`` is ``False`` the byte histogram is skipped (it is
    only consumed by the entropy engine).
    """
    digest = hashlib.sha256()
    byte_counts = [0] * 256 if compute_histogram else None
    file_size = 0
    buffer_view = bytearray()

    with open(filepath, "rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
            file_size += len(chunk)
            if compute_histogram:
                for byte in chunk:
                    byte_counts[byte] += 1
            buffer_view.extend(chunk)

    metrics = {
        "sha256": digest.hexdigest(),
        "byte_counts": byte_counts,
        "file_size": file_size,
    }

    if file_size > max_buffered:
        return None, metrics
    return bytes(buffer_view), metrics
