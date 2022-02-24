# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import pytest

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


def test_get_license_data__sanity():
    # Given
    # When
    license_data = get_licenses_data()
    # Then
    assert isinstance(license_data, dict)


def test_annotate_licenses__happy_path_sdpx_id():
    # Given
    expected_components = [
        {
            "description": "Middleware to set the X-XSS-Protection header",
            "license": "MIT",
            "license_is_deprecated": False,
            "license_is_fsf_libre": True,
            "license_is_osi_approved": True,
            "license_is_professional": True,
            "license_type": "permissive",
            "name": "x-xss-protection",
            "type": "library",
            "version": "1.0.0",
        }
    ]
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-mit-report.json")
    # When
    output_licenses = convert_to_std_object(annotate_licenses(input_sbom))
    # Then
    assert output_licenses == expected_components


def test_annotate_licenses__happy_path_long_name():
    # Given
    expected_components = [
        {
            "description": "Middleware to set the X-XSS-Protection header",
            "license": "MIT",
            "license_is_deprecated": False,
            "license_is_fsf_libre": True,
            "license_is_osi_approved": True,
            "license_is_professional": True,
            "license_type": "permissive",
            "name": "x-xss-protection",
            "type": "library",
            "version": "1.0.0",
        }
    ]
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-mit-long-name-report.json")
    # When
    output_licenses = convert_to_std_object(annotate_licenses(input_sbom))
    # Then
    assert output_licenses == expected_components


def test_annotate_licenses__happy_path_gpl():
    # Given
    expected_components = [
        {
            "description": "Middleware to set the X-XSS-Protection header",
            "license": "GPL-2.0-only",
            "license_is_deprecated": False,
            "license_is_fsf_libre": True,
            "license_is_osi_approved": True,
            "license_is_professional": True,
            "license_type": "copyleft",
            "name": "x-xss-protection",
            "type": "library",
            "version": "1.0.0",
        }
    ]
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-copyleft-report.json")
    # When
    output_licenses = convert_to_std_object(annotate_licenses(input_sbom))
    # Then
    assert output_licenses == expected_components


def test_annotate_licenses__sad_path__unnormalised_standard_id__apache():
    # Given
    expected_components = [
        {
            "description": "Middleware to set the X-XSS-Protection header",
            "license": "Apache-2.0",
            "license_is_deprecated": False,
            "license_is_fsf_libre": True,
            "license_is_osi_approved": True,
            "license_is_professional": True,
            "license_type": "permissive",
            "name": "x-xss-protection",
            "type": "library",
            "version": "1.0.0",
        }
    ]
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-apache-unnormalised-report.json")
    # When
    output_licenses = convert_to_std_object(annotate_licenses(input_sbom))
    # Then
    assert output_licenses == expected_components


def test_annotate_licenses__sad_path__non_standard_id__bsd():
    # Given
    expected_components = [
        {
            "description": "Middleware to set the X-XSS-Protection header",
            "license": "BSD-X.X",
            "license_is_deprecated": None,
            "license_is_fsf_libre": None,
            "license_is_osi_approved": None,
            "license_is_professional": True,
            "license_type": "permissive",
            "name": "x-xss-protection",
            "type": "library",
            "version": "1.0.0",
        }
    ]
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-bsd-pattern-name-report.json")
    # When
    output_licenses = convert_to_std_object(annotate_licenses(input_sbom))
    # Then
    assert output_licenses == expected_components


def test_annotate_licenses__sad_path_unknown():
    # Given
    expected_components = [
        {
            "description": "Middleware to set the X-XSS-Protection header",
            "license": "Unknown License",
            "license_is_deprecated": None,
            "license_is_fsf_libre": None,
            "license_is_osi_approved": None,
            "license_is_professional": None,
            "license_type": "unknown",
            "name": "x-xss-protection",
            "type": "library",
            "version": "1.0.0",
        }
    ]
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-unknown-license-report.json")
    # When
    output_licenses = convert_to_std_object(annotate_licenses(input_sbom))
    # Then
    assert output_licenses == expected_components


def test_check_licenses__happy_path_PROPRIETARY_policy__permissive_ok():
    # Given
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-mit-report.json")
    # When
    [vulnerabilities, warnings] = check_licenses(input_sbom, LicenseScanType.PROPRIETARY.value)
    # Then
    assert convert_to_std_object(vulnerabilities) == []
    assert convert_to_std_object(warnings) == []


def test_check_licenses__sad_path_PROPRIETARY_policy__copyleft_not_ok():
    # Given
    expected_vulnerabilities = [
        {
            "confidence": "",
            "file_location": {"line": 1, "path": "sbom"},
            "identifiers": {},
            "is_excluded": False,
            "is_ignored": False,
            "language": "",
            "metadata": None,
            "name": "Invalid License GPL-2.0-only(x-xss-protection), copyleft license in " "proprietary project",
            "overview": "Strong Copyleft licenses should not be used in Proprietary " "projects",
            "recommendation": "",
            "references": [],
            "severity": "high",
            "version": "",
            "vulnerability_type": "license",
        }
    ]
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-copyleft-report.json")
    # When
    [vulnerabilities, warnings] = check_licenses(input_sbom, LicenseScanType.PROPRIETARY.value)
    # Then
    assert convert_to_std_object(vulnerabilities) == expected_vulnerabilities
    assert convert_to_std_object(warnings) == []


def test_check_licenses__happy_path_PERMISSIVE_policy__permissive_ok():
    # Given
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-mit-report.json")
    # When
    [vulnerabilities, warnings] = check_licenses(input_sbom, LicenseScanType.PERMISSIVE.value)
    # Then
    assert convert_to_std_object(vulnerabilities) == []
    assert convert_to_std_object(warnings) == []


def test_check_licenses__sad_path_PERMISSIVE_policy__copyleft_not_ok():
    # Given
    expected_vulnerabilities = [
        {
            "confidence": "",
            "file_location": {"line": 1, "path": "sbom"},
            "identifiers": {},
            "is_excluded": False,
            "is_ignored": False,
            "language": "",
            "metadata": None,
            "name": "Invalid License GPL-2.0-only(x-xss-protection), copyleft license in "
            "permissive opensource project",
            "overview": "Strong Copyleft licenses should not be used in permissive " "opensource projects",
            "recommendation": "",
            "references": [],
            "severity": "high",
            "version": "",
            "vulnerability_type": "license",
        }
    ]
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-copyleft-report.json")
    # When
    [vulnerabilities, warnings] = check_licenses(input_sbom, LicenseScanType.PERMISSIVE.value)
    # Then
    assert convert_to_std_object(vulnerabilities) == expected_vulnerabilities
    assert convert_to_std_object(warnings) == []


def test_check_licenses__happy_path_OPENSOURCE_policy__permissive_ok():
    # Given
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-mit-report.json")
    # When
    [vulnerabilities, warnings] = check_licenses(input_sbom, LicenseScanType.OPENSOURCE.value)
    # Then
    assert convert_to_std_object(vulnerabilities) == []
    assert convert_to_std_object(warnings) == []


def test_check_licenses__happy_path_OPENSOURCE_policy__copyleft_ok():
    # Given
    expected_vulnerabilities = []
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-copyleft-report.json")
    # When
    [vulnerabilities, warnings] = check_licenses(input_sbom, LicenseScanType.OPENSOURCE.value)
    # Then
    assert convert_to_std_object(vulnerabilities) == expected_vulnerabilities
    assert convert_to_std_object(warnings) == []


def test_check_licenses__sad_path_OPENSOURCE_policy__non_fsf_osi_warns():
    # Given
    expected_vulnerabilities = []
    expected_warnings = [
        "License 'MIT-enna'(x-xss-protection)[sbom], reason: Permissive licenses with "
        "conditions should be manually checked to ensure compliance",
        "License 'MIT-enna'(x-xss-protection)[sbom], reason: Unable to determine if license "
        "is fsf/osi opensource approved",
    ]
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-mit-with-conditions-report.json")
    # When
    [vulnerabilities, warnings] = check_licenses(input_sbom, LicenseScanType.OPENSOURCE.value)
    # Then
    assert convert_to_std_object(vulnerabilities) == expected_vulnerabilities
    assert convert_to_std_object(warnings) == expected_warnings


def test_check_licenses__allowlist():
    # Given
    expected_vulnerabilities = []
    expected_warnings = []
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-mit-with-conditions-report.json")
    input_allowlist = ["MIT-enna"]
    # When
    [vulnerabilities, warnings] = check_licenses(input_sbom, LicenseScanType.OPENSOURCE.value, input_allowlist)
    # Then
    assert convert_to_std_object(vulnerabilities) == expected_vulnerabilities
    assert convert_to_std_object(warnings) == expected_warnings


def test_check_licenses__denylist():
    # Given
    expected_vulnerabilities = [
        {
            "confidence": "",
            "file_location": {"line": 1, "path": "sbom"},
            "identifiers": {},
            "is_excluded": False,
            "is_ignored": False,
            "language": "",
            "metadata": None,
            "name": "License MIT-enna(x-xss-protection), not allowed",
            "overview": "MIT-enna in project license_denylist",
            "recommendation": "",
            "references": [],
            "severity": "high",
            "version": "",
            "vulnerability_type": "license",
        }
    ]
    expected_warnings = []
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-mit-with-conditions-report.json")
    input_denylist = ["MIT-enna"]
    # When
    [vulnerabilities, warnings] = check_licenses(input_sbom, LicenseScanType.OPENSOURCE.value, None, input_denylist)
    # Then
    assert convert_to_std_object(vulnerabilities) == expected_vulnerabilities
    assert convert_to_std_object(warnings) == expected_warnings


def test_check_licenses__no_data():
    # Given
    expected_vulnerabilities = []
    expected_warnings = ["unable to check licenses, no valid license information in sboms"]
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-no-license-data-report.json")
    # When
    [vulnerabilities, warnings] = check_licenses(input_sbom, LicenseScanType.OPENSOURCE.value)
    # Then
    assert convert_to_std_object(vulnerabilities) == expected_vulnerabilities
    assert convert_to_std_object(warnings) == expected_warnings


def test_get_bom_license__id_license():
    # Given
    test_input = {"license": {"id": "Apache"}}
    expected_output = "Apache"
    # When
    output = get_bom_license(test_input)
    # Then
    assert output == expected_output


def test_get_bom_license__name_license():
    # Given
    test_input = {"license": {"name": "Apache-via-name"}}
    expected_output = "Apache-via-name"
    # When
    output = get_bom_license(test_input)
    # Then
    assert output == expected_output


def test_get_bom_license__url_license():
    # Given
    test_input = {"license": {"url": "http://go.microsoft.com/fwlink/?LinkId=329770"}}
    expected_output = "http://go.microsoft.com/fwlink/?LinkId=329770"
    # When
    output = get_bom_license(test_input)
    # Then
    assert output == expected_output


def test_get_bom_license__normalise_unknown():
    # Given
    test_input = {"license": {"name": "UNKNOWN"}}
    expected_output = "unknown"
    # When
    output = get_bom_license(test_input)
    # Then
    assert output == expected_output


def test_normalise_license_id__happy_path():
    # Given
    test_input = "Apache-2.0"
    expected_output = "Apache-2.0"
    # When
    output = normalise_license_id(test_input)
    # Then
    assert output == expected_output


def test_normalise_license_id__sad_path():
    # Given
    test_input = "   Apache 2.0   "
    expected_output = "Apache-2.0"
    # When
    output = normalise_license_id(test_input)
    # Then
    assert output == expected_output


def test_convert_pypi_to_spdx__happy_case():
    # Given
    pypi_license = "License :: CeCILL-C Free Software License Agreement (CECILL-C)"
    expected_license = "CECILL-C"
    # When
    output = convert_pypi_to_spdx(pypi_license)
    # Then
    assert output == expected_license


def test_convert_pypi_to_spdx__sad_case():
    # Given
    pypi_license = "CECILL-C"
    expected_license = None
    # When
    output = convert_pypi_to_spdx(pypi_license)
    # Then
    assert output == expected_license


def test_get_license__pypi_happy_case():
    # Given
    pypi_license = "License :: CeCILL-C Free Software License Agreement (CECILL-C)"
    expected_license = "CECILL-C"
    # When
    output = get_license(pypi_license)
    # Then
    assert output["id"] == expected_license


def test_get_license__pypi_via_patternhappy_case():
    # Given
    pypi_license = "License :: OSI Approved :: BSD License"
    expected_license = {
        "id": "BSD",
        "isDeprecated": None,
        "isFsfLibre": None,
        "isOsiApproved": True,
        "isProfessional": True,
        "name": "Berkeley Software Distribution",
        "reference": "https://en.wikipedia.org/wiki/BSD_licenses",
        "type": "permissive",
    }
    # When
    output = get_license(pypi_license)
    # Then
    assert output == expected_license


def test_get_license__spdx_happy_case():
    # Given
    spdx_license = "CECILL-C"
    expected_license = "CECILL-C"
    # When
    output = get_license(spdx_license)
    # Then
    assert output["id"] == expected_license


def test_get_license__url_happy_case():
    # Given
    url_license = "http://go.microsoft.com/fwlink/?LinkId=329770"
    expected_license_id = url_license
    expected_license_name = "Microsoft .NET Library License"
    # When
    output = get_license(url_license)
    # Then
    assert output["name"] == expected_license_name
    assert output["id"] == expected_license_id


def test_get_license__pattern_happy_case():
    # Given
    long_english_license = "Apache-X.X.X.X-Lorem"
    expected_license_id = long_english_license
    expected_license_name = "Apache License"
    # When
    output = get_license(long_english_license)
    # Then
    assert output["name"] == expected_license_name
    assert output["id"] == expected_license_id


def test_get_license__sad_case():
    # Given
    non_license = "So for license, I put unknown"
    expected_license = None
    # When
    output = get_license(non_license)
    # Then
    assert output == expected_license
