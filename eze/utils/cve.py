""" Tools for parsing and dealing with CVE scores
"""

import re
from urllib.parse import quote

from pydash import py_
from eze.utils.http import request_json
from eze.utils.error import EzeNetworkingError


class CVE:
    """CVE representation"""

    @staticmethod
    def detect_cve(fragment: str):
        """Detect CVE in a text fragment"""
        cve_matcher = re.compile("cve-[0-9-]+", re.IGNORECASE)
        output = re.search(cve_matcher, fragment)
        if output:
            cve_id = fragment[output.start() : output.end()]
            return CVE(cve_id)
        return None

    @staticmethod
    def extract_cve_data(raw_data) -> dict:
        """Extract CVE data from nist JSON data"""
        return py_.get(raw_data, "result.CVE_Items[0]", None)

    @staticmethod
    def to_url(cve_id) -> str:
        """Get url to CVE"""
        return f"https://nvd.nist.gov/vuln/detail/{quote(cve_id)}"

    @staticmethod
    def to_api(cve_id) -> str:
        """Get api url to CVE"""
        return f"https://services.nvd.nist.gov/rest/json/cve/1.0/{quote(cve_id)}"

    @staticmethod
    def get_cve_api(cve_id) -> dict:
        """Get CVE data from nist API

        :raises EzeNetworkingError: on networking error or json decoding error
        """
        api_url = CVE.to_api(cve_id)
        raw_data = request_json(api_url)
        cve_data = CVE.extract_cve_data(raw_data)
        if not cve_data:
            raise EzeNetworkingError(f"unable to find CVE '{cve_id}' data")
        return cve_data

    def __init__(self, cve_id: str):
        """constructor"""
        self.cve_id = cve_id.upper()
        self._cache = None

    def _get_raw(self):
        """
        get raw data

        :raises EzeNetworkingError: on networking error or json decoding error
        """
        if not self._cache:
            self._cache = CVE.get_cve_api(self.cve_id)

        return self._cache

    def get_metadata(self) -> dict:
        """
        create small fragment of CVE for usage

        :raises EzeNetworkingError: on networking error or json decoding error
        """
        cvss_report = self._get_raw()
        severity = py_.get(
            cvss_report,
            "impact.baseMetricV3.cvssV3.baseSeverity",
            py_.get(cvss_report, "impact.baseMetricV2.severity", None),
        )
        return {
            "summary": py_.get(cvss_report, "summary", None),
            "severity": severity,
            "rating": py_.get(cvss_report, "cvss"),
            "url": CVE.to_url(self.cve_id),
            "id": self.cve_id,
            "advisitory_modified": py_.get(cvss_report, "lastModifiedDate", None),
            "advisitory_created": py_.get(cvss_report, "publishedDate", None),
        }
