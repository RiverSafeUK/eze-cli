# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from eze.utils.sbom import check_licenses, annotate_licenses, get_bom_license, get_licenses_data, normalise_license_id

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


def test_check_licenses__happy_path_default_policy():
    # Given
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-mit-report.json")
    # When
    vulnerabilities = check_licenses(input_sbom)
    # Then
    assert vulnerabilities == []


def test_check_licenses__sad_path_default_policy():
    # Given
    input_sbom = load_json_fixture("__fixtures__/sbom/sbom-with-copyleft-report.json")
    # When
    vulnerabilities = check_licenses(input_sbom)
    # Then
    assert vulnerabilities == []


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
