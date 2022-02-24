# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from unittest import mock

from eze.utils.data.cve import detect_cve, get_cve_data, _get_cve_en_summary
from tests.__fixtures__.fixture_helper import get_path_fixture


def test_detect_cve__from_fragment():
    # Given
    expected_cve = "CVE-2014-8991"
    input_fragment = """pip before 6.0 is not using a randomized and secure default build directory when possible. (CvE-2014-8991)."""
    # When
    testee = detect_cve(input_fragment)
    # Then
    assert testee == expected_cve


@mock.patch("urllib.request.urlopen")
def test_get_cve_data__creation_cvss_2(mock_urlopen):
    # Given
    mock_cve_json = get_path_fixture("__fixtures__/cve/services_nvd_nist_gov_rest_json_cve_1_0_CVE_2014_8991.json")
    mock_urlopen.return_value = open(mock_cve_json)
    expected_metadata = {
        "advisory_created": "2014-11-24T15:59Z",
        "advisory_modified": "2021-03-15T16:17Z",
        "id": "CVE-2014-8991",
        "rating": 2.1,
        "severity": "LOW",
        "summary": "pip 1.3 through 1.5.6 allows local users to cause a denial of service (prevention of package"
        " installation) by creating a /tmp/pip-build-* file for another user.",
        "vector": "AV:L/AC:L/Au:N/C:N/I:N/A:P",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-8991",
    }
    # When
    output = get_cve_data("CVE-2014-8991")
    # Then
    assert output == expected_metadata


@mock.patch("urllib.request.urlopen")
def test_get_cve_data__creation_cvss_3_old_data_example(mock_urlopen):
    # Given
    mock_cve_json = get_path_fixture("__fixtures__/cve/services_nvd_nist_gov_rest_json_cve_1_0_CVE_2013_5123.json")
    mock_urlopen.return_value = open(mock_cve_json)
    expected_metadata = {
        "advisory_created": "2019-11-05T22:15Z",
        "advisory_modified": "2019-11-12T19:51Z",
        "id": "CVE-2013-5123",
        "rating": 5.9,
        "severity": "MEDIUM",
        "summary": "The mirroring support (-M, --use-mirrors) in Python Pip before "
        "1.5 uses insecure DNS querying and authenticity checks which "
        "allows attackers to perform man-in-the-middle attacks.",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2013-5123",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
    }
    # When
    output = get_cve_data("CVE-2013-5123")
    # Then
    assert output == expected_metadata


@mock.patch("urllib.request.urlopen")
def test_get_cve_data__creation_cvss_3_new_data_example(mock_urlopen):
    # Given
    mock_cve_json = get_path_fixture("__fixtures__/cve/services_nvd_nist_gov_rest_json_cve_1_0_CVE_2020_8897.json")
    mock_urlopen.return_value = open(mock_cve_json)
    expected_metadata = {
        "advisory_created": "2020-11-16T12:15Z",
        "advisory_modified": "2020-12-02T16:06Z",
        "id": "CVE-2020-8897",
        "rating": 8.1,
        "severity": "HIGH",
        "summary": "A weak robustness vulnerability exists in the AWS Encryption SDKs "
        "for Java, Python, C and Javalcript prior to versions 2.0.0. Due "
        "to the non-committing property of AES-GCM (and other AEAD ciphers "
        "such as AES-GCM-SIV or (X)ChaCha20Poly1305) used by the SDKs to "
        "encrypt messages, an attacker can craft a unique cyphertext which "
        "will decrypt to multiple different results, and becomes "
        "especially relevant in a multi-recipient setting. We recommend "
        "users update their SDK to 2.0.0 or later.",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8897",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    }
    # When
    output = get_cve_data("CVE-2020-8897")
    # Then
    assert output == expected_metadata


def test_get_cve_en_summary__happy_english():
    # Given
    expected = "helloworld en"
    input_fragment = {
        "cve": {
            "description": {
                "description_data": [
                    {"lang": "rs", "value": "helloworld rs"},
                    {"lang": "en", "value": "helloworld en"},
                    {"lang": "cz", "value": "helloworld cz"},
                ]
            }
        },
    }
    # When
    testee = _get_cve_en_summary(input_fragment)
    # Then
    assert testee == expected


def test_get_cve_en_summary__sad_fallback():
    # Given
    expected = "helloworld rs"
    input_fragment = {
        "cve": {
            "description": {
                "description_data": [{"lang": "rs", "value": "helloworld rs"}, {"lang": "cz", "value": "helloworld cz"}]
            }
        },
    }
    # When
    testee = _get_cve_en_summary(input_fragment)
    # Then
    assert testee == expected


def test_get_cve_en_summary__sad_no_data():
    # Given
    expected = None
    input_fragment = {
        "cve": {},
    }
    # When
    testee = _get_cve_en_summary(input_fragment)
    # Then
    assert testee == expected
