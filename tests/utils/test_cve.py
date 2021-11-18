# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from unittest import TestCase, mock

from eze.utils.cve import CVE
from tests.__fixtures__.fixture_helper import get_path_fixture


class TestCVE(TestCase):
    def test_creation__from_fragment(self):
        # Given
        expected_cve = CVE("CVE-2014-8991")
        input_fragment = """pip before 6.0 is not using a randomized and secure default build directory when possible. (CvE-2014-8991)."""
        # When
        testee = CVE.detect_cve(input_fragment)
        # Then
        assert testee.cve_id == expected_cve.cve_id

    @mock.patch("urllib.request.urlopen")
    def test_get_metadata__creation(self, mock_urlopen):
        # Given
        mock_cve_json = get_path_fixture("__fixtures__/cve/cve_circl_lu_api_cve_cve_2014_8991.json")
        mock_urlopen.return_value = open(mock_cve_json)
        expected_metadata = {
            "advisitory_created": "2014-11-24T15:59:00",
            "advisitory_modified": "2021-03-15T16:17:00",
            "id": "CVE-2014-8991",
            "rating": 2.1,
            "severity": "LOW",
            "summary": "pip 1.3 through 1.5.6 allows local users to cause a denial of service (prevention of package"
            " installation) by creating a /tmp/pip-build-* file for another user.",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-8991",
        }
        testee = CVE("CVE-2014-8991")
        # When
        output = testee.get_metadata()
        # Then
        assert output == expected_metadata
