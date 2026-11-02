"""Loads plugin config with yaml.full_load.

VULNERABLE CALL SITE: in PyYAML < 5.4, full_load (FullLoader) can build
arbitrary Python objects from untrusted YAML (CVE-2020-1747, CVE-2020-14343).
A reachability check should flag this file.
"""

import yaml


def load_plugin_config(path):
    with open(path, encoding="utf-8") as f:
        return yaml.full_load(f)
