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
        # The "prompts" key holds the actual payload dicts.
        # Fall back to collecting all list-of-dict values.
        if "prompts" in data and isinstance(data["prompts"], list):
            return data["prompts"]
        payloads: list[dict] = []
        for key, value in data.items():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                payloads.extend(value)
        return payloads if payloads else [data]
    return []
