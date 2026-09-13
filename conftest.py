"""pytest bootstrap.

Keeps the suite hermetic and CWD-independent: the repository root is put on
sys.path so ``import analyzer`` and ``from modules...`` resolve, and the working
directory is forced to the root so relative resources (``iocs/``, reports)
behave exactly like a real run.
"""

import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

os.chdir(PROJECT_ROOT)


def pytest_configure(config):
    for marker in ("integration",):
        config.addinivalue_line("markers", f"{marker}: heavier end-to-end tests")


@pytest.fixture
def write_sample(tmp_path, content=b"plain benign sample\n"):
    def _write(name="sample.txt", data=content):
        path = tmp_path / name
        path.write_bytes(data)
        return str(path)

    return _write