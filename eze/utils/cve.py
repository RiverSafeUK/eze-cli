""" Tools for parsing and dealing with CVE scores
"""

import json
import re
import urllib.request


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
        if not self._cache:
            api_url = self.to_api()
            contents = None

            req = urllib.request.Request(api_url)
            # nosec: Request is being built directly above as a explicit http request
            # hence no risk of unexpected scheme
            with urllib.request.urlopen(req) as stream:  # nosec # nosemgrep
                contents = stream.read()
            self._cache = json.loads(contents)
        return self._cache

    def get_metadata(self) -> dict:
        """create small fragment of CVE for usage"""
        cvss_report = self._get_raw()
        return {
            "summary": cvss_report["summary"],
            "severity": cvss_report["access"]["complexity"],
            "rating": cvss_report["cvss"],
            "url": self.to_url(),
            "id": self.cve_id,
            "advisitory_modified": cvss_report["Modified"],
            "advisitory_created": cvss_report["Published"],
        }
