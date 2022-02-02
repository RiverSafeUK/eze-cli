# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

from tests.__fixtures__.fixture_helper import convert_to_std_object, load_json_fixture
from eze.utils.pypi import filter_license_classifiers, get_pypi_package_data


def test_filter_license_classifiers():
    # Given
    classifiers = [
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Topic :: Software Development :: Testing",
        "Topic :: Security",
        "Topic :: Utilities",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ]
    expected_license = ["License :: OSI Approved :: MIT License"]
    # When
    output = filter_license_classifiers(classifiers)
    # Then
    assert output == expected_license


@mock.patch("eze.utils.pypi.request_json")
@mock.patch("eze.utils.cve.request_json")
def test_get_pypi_package_data__happy_case(mock_cve_request_json, mock_pypi_request_json):
    # Given
    mock_pypi_request_json.return_value = load_json_fixture(
        "__fixtures__/pypi/pypi_org_pypi_aws-encryption-sdk_1_2_0.json"
    )
    mock_cve_request_json.return_value = load_json_fixture(
        "__fixtures__/cve/services_nvd_nist_gov_rest_json_cve_1_0_CVE_2013_5123.json"
    )
    expected_output = {
        "licenses": ["License :: OSI Approved :: Apache Software License"],
        "package_name": "aws-encryption-sdk",
        "package_version": "1.2.0",
        "vulnerabilities": [
            {
                "confidence": "",
                "file_location": {"line": 0, "path": "requirements.txt"},
                "identifiers": {"CVE": "CVE-2020-8897", "PYSEC": "PYSEC-2020-261"},
                "is_excluded": False,
                "is_ignored": False,
                "language": "",
                "metadata": None,
                "name": "aws-encryption-sdk",
                "overview": "The mirroring support (-M, --use-mirrors) in "
                "Python Pip before 1.5 uses insecure DNS "
                "querying and authenticity checks which allows "
                "attackers to perform man-in-the-middle attacks.",
                "recommendation": "Update package to non-vulnerable " "version 2.0.0",
                "references": [],
                "severity": "medium",
                "version": "1.2.0",
                "vulnerability_type": "dependency",
            }
        ],
        "warnings": [],
    }
    # When
    output = get_pypi_package_data("aws-encryption-sdk", "1.2.0", "requirements.txt")
    # Then
    assert convert_to_std_object(output) == expected_output
