"""Loads app settings with yaml.safe_load.

SAFE CALL SITE: safe_load is not affected by the FullLoader CVEs.
A reachability check should NOT flag this file.
"""

import yaml


def load_settings(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)
