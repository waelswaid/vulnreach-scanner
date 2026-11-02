# PyYAML test project

A fake project for testing depscan. Never install or run it.

- `requirements.txt` pins `PyYAML==5.3`, which has two known critical
  vulnerabilities: CVE-2020-1747 (fixed in 5.3.1) and CVE-2020-14343
  (fixed in 5.4).
- `app/config_loader.py` calls `yaml.full_load`, the vulnerable function.
- `app/settings.py` calls only `yaml.safe_load`, which is not affected.

Expected results:

- v0.1: both PyYAML vulnerabilities flagged, upgrade target 5.4.
- Reachability (later): reachable in `config_loader.py`, not in `settings.py`.
