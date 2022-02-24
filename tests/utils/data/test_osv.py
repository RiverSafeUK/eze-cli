# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

from eze.utils.io.print import pretty_print_json

from tests.__fixtures__.fixture_helper import load_json_fixture, convert_to_std_object, get_snapshot_directory
from eze.utils.data.osv import from_maven_package_to_osv_id, get_osv_package_data, get_recommendation


def test_from_maven_package_to_osv_id__happy_case():
    input = "org.apache.logging.log4j/log4j-api"
    expected = "org.apache.logging.log4j.log4j-api"
    assert from_maven_package_to_osv_id(input) == expected


def test_from_maven_package_to_osv_id__happy_nothing_case():
    input = "org.apache.logging.log4j.log4j-api"
    expected = "org.apache.logging.log4j.log4j-api"
    assert from_maven_package_to_osv_id(input) == expected


@mock.patch("eze.utils.data.osv.request_json")
def test_get_osv_package_data__happy_case(mock_osv_request_json, snapshot):
    # Given
    mock_osv_request_json.return_value = load_json_fixture(
        "__fixtures__/osv/osv-org-opencastproject-opencast-kernel.json"
    )
    expected_output = {
        "licenses": ["License :: OSI Approved :: Apache Software License"],
        "package_name": "aws-encryption-sdk",
        "package_version": "1.2.0",
        "vulnerabilities": [
            {
                "confidence": "",
                "file_location": {"line": 1, "path": "requirements.txt"},
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
    output = get_osv_package_data("Maven", "org.opencastproject:opencast-kernel", "8.0", "pom.xml")
    # Then
    snapshot.snapshot_dir = get_snapshot_directory()
    std_output = pretty_print_json(output)
    snapshot.assert_match(convert_to_std_object(std_output), "utils/osv/get_osv_package_data_snapshot.json")


def test_get_recommendation__happy_case():
    example_vuln_input = {
        "id": "GHSA-44cw-p2hm-gpf6",
        "summary": "xxx",
        "details": "xxx",
        "aliases": [],
        "modified": "2022-02-08T23:07:51.549040Z",
        "published": "2020-12-08T22:37:59Z",
        "references": [],
        "affected": [
            {
                "package": {
                    "name": "org.opencastproject:opencast-kernel",
                    "ecosystem": "Maven",
                    "purl": "pkg:maven/org.opencastproject:opencast-kernel",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"introduced": "8.0"}, {"fixed": "8.9"}, {"fixed": "7.9"}],
                    }
                ],
                "versions": ["6.6", "7.2", "7.3", "8.7", "8.8"],
                "database_specific": {},
            }
        ],
        "schema_version": "1.2.0",
    }
    expected_output = "Update package to non-vulnerable version 8.9,7.9"

    # When
    output = get_recommendation(example_vuln_input, "org.opencastproject:opencast-kernel")
    # Then
    assert output == expected_output
