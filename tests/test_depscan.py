"""Unit tests for depscan's pure functions.

Run from the repository root:
    python -m unittest
"""

import unittest

import depscan


class VersionKeyTest(unittest.TestCase):
    def assert_order(self, lower, higher):
        self.assertLess(
            depscan.version_key(lower),
            depscan.version_key(higher),
            f"expected {lower!r} < {higher!r}",
        )

    def test_numeric_parts_compare_numerically(self):
        self.assert_order("1.9.2", "1.10.0")

    def test_two_part_version_below_higher_patch(self):
        self.assert_order("5.3", "5.3.1")

    def test_trailing_zero_is_same_version(self):
        self.assertEqual(depscan.version_key("5.4"), depscan.version_key("5.4.0"))

    def test_rc_sorts_below_final(self):
        self.assert_order("5.4rc1", "5.4")

    def test_dashed_rc_sorts_below_final(self):
        self.assert_order("1.2.3-rc1", "1.2.3")

    def test_beta_sorts_below_final(self):
        self.assert_order("2.0.0b1", "2.0.0")

    def test_prereleases_order_among_themselves(self):
        self.assert_order("2.0.0a1", "2.0.0b1")
        self.assert_order("2.0.0b1", "2.0.0rc1")
        self.assert_order("2.0.0rc1", "2.0.0rc2")

    def test_post_release_sorts_above_final(self):
        self.assert_order("1.2.3", "1.2.3.post1")


class NormalizeNameTest(unittest.TestCase):
    def test_pypi_dash_underscore_dot_are_equal(self):
        self.assertEqual(
            depscan.normalize_name("Typing_Extensions", "PyPI"),
            depscan.normalize_name("typing-extensions", "PyPI"),
        )

    def test_other_ecosystems_only_lowercase(self):
        self.assertEqual(depscan.normalize_name("My.Pkg", "npm"), "my.pkg")
        self.assertNotEqual(
            depscan.normalize_name("my-pkg", "npm"),
            depscan.normalize_name("my.pkg", "npm"),
        )


class SeverityFromCvssTest(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(depscan.severity_from_cvss("9.8"), "critical")
        self.assertEqual(depscan.severity_from_cvss("9.0"), "critical")
        self.assertEqual(depscan.severity_from_cvss("7.0"), "high")
        self.assertEqual(depscan.severity_from_cvss("4.0"), "moderate")
        self.assertEqual(depscan.severity_from_cvss("0.1"), "low")

    def test_zero_and_garbage_give_none(self):
        self.assertIsNone(depscan.severity_from_cvss("0"))
        self.assertIsNone(depscan.severity_from_cvss("not a score"))
        self.assertIsNone(depscan.severity_from_cvss(None))


class SeverityFromAdvisoriesTest(unittest.TestCase):
    def test_picks_worst_and_maps_medium_to_moderate(self):
        vulns = [
            {"database_specific": {"severity": "MEDIUM"}},
            {"database_specific": {"severity": "HIGH"}},
        ]
        self.assertEqual(depscan.severity_from_advisories(vulns), "high")
        self.assertEqual(
            depscan.severity_from_advisories(vulns[:1]), "moderate"
        )

    def test_no_usable_label_gives_none(self):
        self.assertIsNone(depscan.severity_from_advisories([{}]))


class PickPrimaryIdTest(unittest.TestCase):
    def test_prefers_ghsa(self):
        self.assertEqual(
            depscan.pick_primary_id(["PYSEC-2021-142", "GHSA-8q59-q68h-6hv4"]),
            "GHSA-8q59-q68h-6hv4",
        )

    def test_falls_back_to_first(self):
        self.assertEqual(
            depscan.pick_primary_id(["PYSEC-2021-142", "CVE-2020-14343"]),
            "PYSEC-2021-142",
        )


class NormalizeVersionTest(unittest.TestCase):
    def test_drops_trailing_zero_parts(self):
        self.assertEqual(depscan.normalize_version("5.3.0"), "5.3")
        self.assertEqual(depscan.normalize_version("1.0.0"), "1")
        self.assertEqual(depscan.normalize_version("5.3"), "5.3")


def make_vuln(vuln_id, package_name, fixed_versions, range_type="ECOSYSTEM"):
    return {
        "id": vuln_id,
        "affected": [
            {
                "package": {"name": package_name},
                "ranges": [
                    {
                        "type": range_type,
                        "events": [{"fixed": v} for v in fixed_versions],
                    }
                ],
            }
        ],
    }


class FindFixedVersionTest(unittest.TestCase):
    def test_picks_lowest_fix_above_installed(self):
        vulns = [make_vuln("GHSA-x", "pyyaml", ["5.3.1", "5.4"])]
        package = {"name": "pyyaml", "version": "5.3", "ecosystem": "PyPI"}
        self.assertEqual(depscan.find_fixed_version(vulns, package), "5.3.1")

    def test_none_when_no_fix_above_installed(self):
        vulns = [make_vuln("GHSA-x", "pyyaml", ["5.3.1"])]
        package = {"name": "pyyaml", "version": "5.4", "ecosystem": "PyPI"}
        self.assertIsNone(depscan.find_fixed_version(vulns, package))

    def test_ignores_git_ranges(self):
        vulns = [make_vuln("GHSA-x", "pyyaml", ["a001f27"], range_type="GIT")]
        package = {"name": "pyyaml", "version": "5.3", "ecosystem": "PyPI"}
        self.assertIsNone(depscan.find_fixed_version(vulns, package))

    def test_pypi_names_match_across_dash_underscore(self):
        vulns = [make_vuln("GHSA-x", "typing-extensions", ["4.1.0"])]
        package = {
            "name": "typing_extensions",
            "version": "4.0.0",
            "ecosystem": "PyPI",
        }
        self.assertEqual(depscan.find_fixed_version(vulns, package), "4.1.0")


def make_result(source_type, source_path, package, vulns, groups):
    return {
        "source": {"type": source_type, "path": source_path},
        "packages": [
            {"package": package, "vulnerabilities": vulns, "groups": groups}
        ],
    }


class ParseFindingsTest(unittest.TestCase):
    def test_one_finding_per_group(self):
        vulns = [
            dict(make_vuln("GHSA-8q59-q68h-6hv4", "pyyaml", ["5.4"]),
                 summary="Improper Input Validation in PyYAML"),
            dict(make_vuln("PYSEC-2021-142", "pyyaml", ["5.4"])),
        ]
        groups = [
            {
                "ids": ["PYSEC-2021-142", "GHSA-8q59-q68h-6hv4"],
                "aliases": ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4",
                            "PYSEC-2021-142"],
                "max_severity": "9.8",
            }
        ]
        osv_json = {
            "results": [
                make_result(
                    "lockfile",
                    "requirements.txt",
                    {"name": "pyyaml", "version": "5.3", "ecosystem": "PyPI"},
                    vulns,
                    groups,
                )
            ]
        }
        findings = depscan.parse_findings(osv_json, ".")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["vulnerability_id"], "GHSA-8q59-q68h-6hv4")
        self.assertEqual(finding["aliases"], ["CVE-2020-14343", "PYSEC-2021-142"])
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["fixed_version"], "5.4")
        self.assertEqual(finding["summary"],
                         "Improper Input Validation in PyYAML")

    def test_resolved_duplicate_of_lockfile_entry_is_skipped(self):
        package_listed = {"name": "pyyaml", "version": "5.3", "ecosystem": "PyPI"}
        package_resolved = {"name": "pyyaml", "version": "5.3.0", "ecosystem": "PyPI"}
        vulns = [make_vuln("GHSA-x", "pyyaml", ["5.4"])]
        groups = [{"ids": ["GHSA-x"], "aliases": [], "max_severity": "9.8"}]
        osv_json = {
            "results": [
                # Resolved tree deliberately listed first: parse_findings
                # must still prefer the lockfile entry.
                make_result("resolved", "requirements.txt",
                            package_resolved, vulns, groups),
                make_result("lockfile", "requirements.txt",
                            package_listed, vulns, groups),
            ]
        }
        findings = depscan.parse_findings(osv_json, ".")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["version"], "5.3")

    def test_pypi_duplicate_across_dash_underscore_is_skipped(self):
        vulns = [make_vuln("GHSA-x", "typing-extensions", ["4.1.0"])]
        groups = [{"ids": ["GHSA-x"], "aliases": [], "max_severity": "7.5"}]
        osv_json = {
            "results": [
                make_result(
                    "lockfile", "requirements.txt",
                    {"name": "typing_extensions", "version": "4.0.0",
                     "ecosystem": "PyPI"},
                    vulns, groups,
                ),
                make_result(
                    "resolved", "requirements.txt",
                    {"name": "typing-extensions", "version": "4.0.0",
                     "ecosystem": "PyPI"},
                    vulns, groups,
                ),
            ]
        }
        findings = depscan.parse_findings(osv_json, ".")
        self.assertEqual(len(findings), 1)

    def test_group_without_ids_is_skipped(self):
        vulns = [make_vuln("GHSA-x", "pyyaml", ["5.4"])]
        groups = [
            {"ids": [], "aliases": [], "max_severity": "9.8"},
            {"ids": ["GHSA-x"], "aliases": [], "max_severity": "9.8"},
        ]
        osv_json = {
            "results": [
                make_result("lockfile", "requirements.txt",
                            {"name": "pyyaml", "version": "5.3",
                             "ecosystem": "PyPI"},
                            vulns, groups)
            ]
        }
        findings = depscan.parse_findings(osv_json, ".")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability_id"], "GHSA-x")

    def test_sorted_by_severity_then_package(self):
        def result_for(name, severity_score, vuln_id):
            vulns = [make_vuln(vuln_id, name, [])]
            groups = [{"ids": [vuln_id], "aliases": [],
                       "max_severity": severity_score}]
            return make_result(
                "lockfile", "requirements.txt",
                {"name": name, "version": "1.0", "ecosystem": "PyPI"},
                vulns, groups,
            )

        osv_json = {
            "results": [
                result_for("aaa", "4.2", "GHSA-low"),
                result_for("zzz", "9.8", "GHSA-crit"),
            ]
        }
        findings = depscan.parse_findings(osv_json, ".")
        self.assertEqual(
            [f["vulnerability_id"] for f in findings],
            ["GHSA-crit", "GHSA-low"],
        )


if __name__ == "__main__":
    unittest.main()
