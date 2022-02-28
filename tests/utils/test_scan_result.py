# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import pytest
from eze.core.tool import ScanResult

from eze.core.enums import LicenseScanType
from eze.utils.license import (
    check_licenses,
    annotate_licenses,
    get_bom_license,
    get_licenses_data,
    normalise_license_id,
    get_license,
    convert_pypi_to_spdx,
)

from tests.__fixtures__.fixture_helper import load_json_fixture, convert_to_std_object
from eze.utils.scan_result import has_sbom_data, has_vulnerability_data


def test_has_sbom_data__happypath_no_sbom():
    # Given
    scan_result: ScanResult = ScanResult({})
    expected_output = False
    # When
    output = has_sbom_data(scan_result)
    # Then
    assert output == expected_output


def test_has_sbom_data__happypath_empty_sbom():
    # Given
    scan_result: ScanResult = ScanResult({"sboms": {}})
    expected_output = False
    # When
    output = has_sbom_data(scan_result)
    # Then
    assert output == expected_output


def test_has_sbom_data__happypath_one_sbom():
    # Given
    scan_result: ScanResult = ScanResult(
        {"sboms": {"example-sbom": load_json_fixture("__fixtures__/sbom/sbom-with-mit-report.json")}}
    )
    expected_output = True
    # When
    output = has_sbom_data(scan_result)
    # Then
    assert output == expected_output


def test_has_vulnerability_data__happypath_true_vulns_sbom():
    # Given
    scan_result: ScanResult = ScanResult(
        {
            "vulnerabilities": [{"name": "example vuln"}],
            "sboms": {"example-sbom": load_json_fixture("__fixtures__/sbom/sbom-with-mit-report.json")},
        }
    )
    expected_output = True
    # When
    output = has_vulnerability_data(scan_result)
    # Then
    assert output == expected_output


def test_has_vulnerability_data__happypath_true_no_vulns_no_sbom():
    # Given
    scan_result: ScanResult = ScanResult({})
    expected_output = True
    # When
    output = has_vulnerability_data(scan_result)
    # Then
    assert output == expected_output


def test_has_vulnerability_data__happypath_false_no_vulns_no_sbom_one_sbom():
    # NOTE: assumed to be no vulnerability data when no vulns but sbom data
    # Given
    scan_result: ScanResult = ScanResult(
        {"sboms": {"example-sbom": load_json_fixture("__fixtures__/sbom/sbom-with-mit-report.json")}}
    )
    expected_output = False
    # When
    output = has_vulnerability_data(scan_result)
    # Then
    assert output == expected_output
