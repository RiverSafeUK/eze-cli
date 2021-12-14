""" Tools for parsing and dealing with CVE scores
"""

import re
from eze.utils.http import request_json
from pydash import py_


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

    def __init__(self, cve_id: str):
        """constructor"""
        self.cve_id = cve_id.upper()
        self._cache = None

    def to_url(self) -> str:
        """Get url to CVE"""
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"

    def to_api(self) -> str:
        """Get api url to CVE"""
        return f"https://cve.circl.lu/api/cve/{self.cve_id}"

    def _get_raw(self):
        """
        get raw data

        :raises EzeNetworkingError: on networking error or json decoding error
        """
        if not self._cache:
            api_url = self.to_api()
            self._cache = request_json(api_url)

        return self._cache

    def get_metadata(self) -> dict:
        """
        create small fragment of CVE for usage

        :raises EzeNetworkingError: on networking error or json decoding error
        """
        cvss_report = self._get_raw()
        return {
            "summary": py_.get(cvss_report, "summary", None),
            "severity": py_.get(cvss_report, "access.complexity", None),
            "rating": py_.get(cvss_report, "cvss"),
            "url": self.to_url(),
            "id": self.cve_id,
            "advisitory_modified": py_.get(cvss_report, "Modified", None),
            "advisitory_created": py_.get(cvss_report, "Published", None),
        }
