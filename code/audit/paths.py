"""Cross-platform paths rooted at the repository containing this module."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "dataset"


def repo_root() -> Path:
    """Return the repository root, independent of the caller's working directory."""

    return REPO_ROOT


def dataset_dir() -> Path:
    """Return the participant-facing dataset directory."""

    return DATASET_DIR


def dataset_file(name: str) -> Path:
    """Return a named file inside the participant-facing dataset directory."""

    return DATASET_DIR / name
