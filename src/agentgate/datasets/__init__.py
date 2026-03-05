"""YAML dataset loader for attack payloads."""

from __future__ import annotations

from pathlib import Path

import yaml

_DATASETS_DIR = Path(__file__).parent


def load_payloads(category: str) -> list[dict]:
    """Load test payloads from a YAML dataset file.

    Args:
        category: Name of the dataset (e.g. "harmful_content").

    Returns:
        List of payload dicts as defined in the YAML file.
    """
    path = _DATASETS_DIR / f"{category}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    with open(path) as f:
        data = yaml.safe_load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Support both flat list and grouped format
        payloads: list[dict] = []
        for key, value in data.items():
            if isinstance(value, list):
                payloads.extend(value)
        return payloads if payloads else [data]
    return []
