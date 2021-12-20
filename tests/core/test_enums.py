# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,invalid-name
import json

from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum, Vulnerability
from tests.__fixtures__.fixture_helper import assert_deep_equal


class TestVulnerability:
    def test_serialisation_test(self):
        old_vulnerability = Vulnerability(
            {
                "vulnerability_type": VulnerabilityType.dependency.name,
                "severity": "low",
                "is_ignored": False,
                "name": "foo",
                "identifiers": {"CVE": "cve-something"},
            }
        )
        dehydrated_vulnerability_json = json.loads(json.dumps(old_vulnerability, default=vars))
        new_rehyrdated_vulnerability = Vulnerability(dehydrated_vulnerability_json)

        assert_deep_equal(old_vulnerability, new_rehyrdated_vulnerability)

    def test_update_ignored__false(self):
        # Given
        expected_ignored_status = False
        input_vulnerability = Vulnerability(
            {
                "name": "foo",
                "identifiers": {"CVE": "cve-xxxx"},
                "severity": VulnerabilitySeverityEnum.medium.name,
                "is_ignored": False,
            }
        )

        input_config = {
            "DEFAULT_SEVERITY": "medium",
            "IGNORED_VULNERABILITIES": [],
            "IGNORE_BELOW_SEVERITY_INT": VulnerabilitySeverityEnum.na.value,
        }

        # When
        input_vulnerability.update_ignored(input_config)
        # Then
        assert input_vulnerability.is_ignored == expected_ignored_status

    def test_update_ignored__by_severity(self):
        # Given
        expected_ignored_status = True
        input_vulnerability = Vulnerability(
            {
                "name": "foo",
                "identifiers": {"CVE": "cve-xxxx"},
                "severity": VulnerabilitySeverityEnum.medium.name,
                "is_ignored": False,
            }
        )

        input_config = {
            "DEFAULT_SEVERITY": "medium",
            "IGNORED_VULNERABILITIES": [],
            "IGNORE_BELOW_SEVERITY_INT": VulnerabilitySeverityEnum.high.value,
        }

        # When
        input_vulnerability.update_ignored(input_config)
        # Then
        assert input_vulnerability.is_ignored == expected_ignored_status

    def test_update_ignored__by_name(self):
        # Given
        expected_ignored_status = True
        input_vulnerability = Vulnerability(
            {
                "name": "foo",
                "identifiers": {"CVE": "cve-xxxx"},
                "severity": VulnerabilitySeverityEnum.medium.name,
                "is_ignored": False,
            }
        )

        input_config = {
            "DEFAULT_SEVERITY": "medium",
            "IGNORED_VULNERABILITIES": ["foo"],
            "IGNORE_BELOW_SEVERITY_INT": VulnerabilitySeverityEnum.na.value,
        }

        # When
        input_vulnerability.update_ignored(input_config)
        # Then
        assert input_vulnerability.is_ignored == expected_ignored_status

    def test_update_ignored__by_cve(self):
        # Given
        expected_ignored_status = True
        input_vulnerability = Vulnerability(
            {
                "name": "foo",
                "identifiers": {"CVE": "cve-xxxx"},
                "severity": VulnerabilitySeverityEnum.medium.name,
                "is_ignored": False,
            }
        )

        input_config = {
            "DEFAULT_SEVERITY": "medium",
            "IGNORED_VULNERABILITIES": ["cve-xxxx"],
            "IGNORE_BELOW_SEVERITY_INT": VulnerabilitySeverityEnum.na.value,
        }

        # When
        input_vulnerability.update_ignored(input_config)
        # Then
        assert input_vulnerability.is_ignored == expected_ignored_status
