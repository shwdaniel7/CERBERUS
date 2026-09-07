import hashlib


CHUNK_SIZE = 1024 * 1024


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
