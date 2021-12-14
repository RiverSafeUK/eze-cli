# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from eze.utils.sbom import check_licenses

from tests.__fixtures__.fixture_helper import get_path_fixture


def test_check_licenses__happy_path_default_policy():
    # Given
    input_sbom = get_path_fixture("__fixtures__/sbom/sbom-with-mit-report.json")
    # When
    vulnerabilities = check_licenses(input_sbom)
    # Then
    assert vulnerabilities == []


def test_check_licenses__sad_path_default_policy():
    # Given
    input_sbom = get_path_fixture("__fixtures__/sbom/sbom-with-copyleft-report.json")
    # When
    vulnerabilities = check_licenses(input_sbom)
    # Then
    assert vulnerabilities == []
