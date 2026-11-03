"""depscan v0.1: flag vulnerable dependencies using osv-scanner.

Runs osv-scanner on a project, reshapes its JSON into simple findings,
prints a readable report, and writes the findings to a JSON file.

Usage:
    python depscan.py <project-path> [--output findings.json]
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = {"critical": 4, "high": 3, "moderate": 2, "low": 1, "unknown": 0}

INSTALL_HELP = (
    "osv-scanner was not found on your PATH.\n"
    "Install it with one of:\n"
    "  winget install Google.OSVScanner\n"
    "  brew install osv-scanner\n"
    "  go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest\n"
    "or download a release from https://github.com/google/osv-scanner/releases"
)


class ScanError(Exception):
    """Raised when osv-scanner cannot be run or its output cannot be read."""


def find_osv_scanner():
    path = shutil.which("osv-scanner")
    if path is None:
        raise ScanError(INSTALL_HELP)
    return path


def get_osv_scanner_version(exe):
    result = subprocess.run(
        [exe, "--version"], capture_output=True, text=True, encoding="utf-8"
    )
    match = re.search(r"osv-scanner version:\s*(\S+)", result.stdout)
    return match.group(1) if match else "unknown"


def run_osv_scanner(exe, path, resolve=True):
    """Run osv-scanner on `path` and return its parsed JSON output.

    With resolve=True, osv-scanner also works out transitive dependencies
    of manifest files like requirements.txt. We use the "native" data
    source (live PyPI/npm) because the default (deps.dev) can pick
    outdated versions and report vulnerabilities a fresh install wouldn't have.
    With resolve=False, only the packages listed in the files are checked.
    """
    cmd = [exe, "scan", "source", "--format", "json"]
    cmd += ["--data-source", "native"] if resolve else ["--no-resolve"]
    cmd += ["-r", str(path)]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    # Exit codes: 0 = no vulnerabilities, 1 = vulnerabilities found,
    # 128 = no packages found. Anything else is a real error.
    if result.returncode == 128:
        return {"results": [], "no_packages": True}
    if result.returncode not in (0, 1):
        raise ScanError(
            f"osv-scanner failed (exit code {result.returncode}):\n{result.stderr.strip()}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ScanError(f"Could not read osv-scanner output as JSON: {exc}") from exc


def severity_from_cvss(score):
    """Turn a CVSS score string like "9.8" into a severity label."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "moderate"
    if value > 0:
        return "low"
    return None


def severity_from_advisories(vulns):
    """Fall back to the advisory's own rating (e.g. GitHub's "HIGH")."""
    best = None
    for vuln in vulns:
        label = str((vuln.get("database_specific") or {}).get("severity", "")).lower()
        if label == "medium":
            label = "moderate"
        if label in SEVERITY_ORDER and (
            best is None or SEVERITY_ORDER[label] > SEVERITY_ORDER[best]
        ):
            best = label
    return best


PRE_RELEASE_RANK = {
    "dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2,
    "c": 3, "pre": 3, "preview": 3, "rc": 3,
}


def version_key(version):
    """Rough sortable key for version strings ("1.10.0" > "1.9.2" > "1.9.2rc1").

    Trailing ".0" parts are ignored ("5.4" equals "5.4.0") and common
    pre-release suffixes (a, b, rc, dev, ...) sort below the final release.
    Good enough for picking a fix version; not a full PEP 440 / semver parser.
    """
    tokens = re.findall(r"\d+|[A-Za-z]+", version)
    release = []
    while tokens and tokens[0].isdigit():
        release.append(int(tokens.pop(0)))
    while release and release[-1] == 0:
        release.pop()
    if not tokens:
        suffix = (1,)  # final release
    else:
        rank = PRE_RELEASE_RANK.get(tokens[0].lower())
        number = int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else 0
        if rank is not None:
            suffix = (0, rank, number)  # pre-release: below the final
        else:
            suffix = (2, tokens[0].lower(), number)  # post/local/unknown: above
    return (tuple(release), suffix)


def normalize_name(name, ecosystem=""):
    """Normalize a package name for comparison.

    PyPI treats "-", "_" and "." in names as interchangeable (PEP 503), so
    "typing_extensions" and "typing-extensions" are the same package. Other
    ecosystems are only compared case-insensitively.
    """
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def find_fixed_version(vulns, package):
    """Lowest fixed version above the installed version, or None if no fix exists."""
    installed = version_key(package["version"])
    ecosystem = package.get("ecosystem", "")
    name = normalize_name(package["name"], ecosystem)
    candidates = set()
    for vuln in vulns:
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            if normalize_name(pkg.get("name", ""), ecosystem) != name:
                continue
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if fixed and rng.get("type") != "GIT":
                        candidates.add(fixed)
    above = [v for v in candidates if version_key(v) > installed]
    if not above:
        return None
    return min(above, key=version_key)


def pick_summary(vulns):
    for vuln in vulns:
        if vuln.get("summary"):
            return vuln["summary"].strip()
    for vuln in vulns:
        if vuln.get("details"):
            first_line = vuln["details"].strip().splitlines()[0]
            return first_line[:200]
    return ""


def pick_primary_id(ids):
    """Prefer the GitHub advisory ID, then the first ID osv-scanner lists."""
    for vuln_id in ids:
        if vuln_id.startswith("GHSA-"):
            return vuln_id
    return ids[0]


def normalize_version(version):
    """Drop trailing ".0" parts so "5.3" and "5.3.0" count as the same version."""
    parts = version.split(".")
    while len(parts) > 1 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts)


def parse_findings(osv_json, project_root):
    """Reshape osv-scanner JSON into a flat list of findings.

    osv-scanner groups advisories that describe the same issue
    (e.g. a PYSEC and a GHSA entry), so we make one finding per group.

    For a requirements.txt it also returns two results for the same file:
    the packages listed in the file (source type "lockfile") and the fully
    resolved dependency tree. We read the listed packages first and skip
    duplicates from the resolved tree (which may spell "5.3" as "5.3.0").

    Findings don't say whether a package is direct or transitive yet;
    see TODO.md.
    """
    results = sorted(
        osv_json.get("results") or [],
        key=lambda r: r.get("source", {}).get("type") != "lockfile",
    )
    seen = set()
    findings = []
    for result in results:
        source = result.get("source", {}).get("path", "")
        try:
            source = str(Path(source).resolve().relative_to(Path(project_root).resolve()))
        except ValueError:
            pass
        for entry in result.get("packages") or []:
            package = entry["package"]
            key = (
                source,
                package.get("ecosystem", ""),
                normalize_name(package["name"], package.get("ecosystem", "")),
                normalize_version(package["version"]),
            )
            if key in seen:
                continue
            seen.add(key)
            vulns_by_id = {v["id"]: v for v in entry.get("vulnerabilities") or []}
            for group in entry.get("groups") or []:
                if not group.get("ids"):
                    continue
                vulns = [vulns_by_id[i] for i in group["ids"] if i in vulns_by_id]
                primary = pick_primary_id(group["ids"])
                aliases = sorted(set(group.get("aliases", [])) - {primary})
                severity = (
                    severity_from_cvss(group.get("max_severity"))
                    or severity_from_advisories(vulns)
                    or "unknown"
                )
                findings.append(
                    {
                        "package": package["name"],
                        "version": package["version"],
                        "ecosystem": package.get("ecosystem", ""),
                        "vulnerability_id": primary,
                        "aliases": aliases,
                        "severity": severity,
                        "cvss_score": group.get("max_severity") or None,
                        "fixed_version": find_fixed_version(vulns, package),
                        "summary": pick_summary(vulns),
                        "source_file": source,
                    }
                )
    findings.sort(
        key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["package"], f["vulnerability_id"])
    )
    return findings


def print_report(findings, project_root):
    print(f"\ndepscan report for {project_root}\n")
    if not findings:
        print("No known vulnerabilities found.")
        return

    by_package = {}
    for finding in findings:
        key = (finding["package"], finding["version"], finding["ecosystem"])
        by_package.setdefault(key, []).append(finding)

    # Packages with the most severe issue first.
    ordered = sorted(
        by_package.items(),
        key=lambda item: (
            -max(SEVERITY_ORDER[f["severity"]] for f in item[1]),
            item[0][0],
        ),
    )
    for (name, version, ecosystem), items in ordered:
        fixes = [f["fixed_version"] for f in items if f["fixed_version"]]
        upgrade = max(fixes, key=version_key) if fixes else None
        upgrade_text = f"upgrade to {upgrade}" if upgrade else "no fix available"
        print(f"{name} {version} ({ecosystem}) - {upgrade_text}")
        print(f"  found in {items[0]['source_file']}")
        for f in items:
            cve = next((a for a in f["aliases"] if a.startswith("CVE-")), None)
            label = f["vulnerability_id"] + (f" / {cve}" if cve else "")
            fixed = f["fixed_version"] or "no fix"
            print(f"  [{f['severity'].upper():<8}] {label}  (fixed in {fixed})")
            if f["summary"]:
                print(f"             {f['summary']}")
        print()

    package_word = "package" if len(by_package) == 1 else "packages"
    vuln_word = "vulnerability" if len(findings) == 1 else "vulnerabilities"
    print(f"{len(findings)} {vuln_word} in {len(by_package)} {package_word}")


def write_json(findings, out_path, project_root, osv_version, resolve):
    report = {
        "tool": "depscan",
        "tool_version": "0.1",
        "osv_scanner_version": osv_version,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(Path(project_root).resolve()),
        # "native" = transitive deps resolved from live registries;
        # "none" = only packages listed in the dependency files.
        "resolution": "native" if resolve else "none",
        "findings": findings,
    }
    Path(out_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Flag vulnerable dependencies using osv-scanner."
    )
    parser.add_argument("path", help="project directory to scan")
    parser.add_argument(
        "--output", "-o", default="findings.json", help="JSON output file (default: findings.json)"
    )
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="only check packages listed in dependency files; skip transitive dependencies",
    )
    args = parser.parse_args(argv)
    resolve = not args.no_resolve

    project_root = Path(args.path)
    if not project_root.is_dir():
        print(f"error: {project_root} is not a directory", file=sys.stderr)
        return 2

    try:
        exe = find_osv_scanner()
        osv_version = get_osv_scanner_version(exe)
        osv_json = run_osv_scanner(exe, project_root, resolve=resolve)
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if osv_json.get("no_packages"):
        print(f"warning: no dependency files found in {project_root}", file=sys.stderr)

    findings = parse_findings(osv_json, project_root)
    print_report(findings, project_root)
    write_json(findings, args.output, project_root, osv_version, resolve)
    print(f"\nJSON written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
