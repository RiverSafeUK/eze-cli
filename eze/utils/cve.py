""" Tools for parsing and dealing with CVE scores
"""

import re
from urllib.parse import quote

from pydash import py_
from eze.utils.http import request_json
from eze.utils.error import EzeNetworkingError

CVE_IN_TEXT_RE = re.compile("cve-[0-9-]+", re.IGNORECASE)


def detect_cve(fragment: str):
    """Detect CVE in a text fragment"""
    output = re.search(CVE_IN_TEXT_RE, fragment)
    if not output:
        return None
    return fragment[output.start() : output.end()].upper()


def to_url(cve_id: str) -> str:
    """Get url to CVE"""
    return f"https://nvd.nist.gov/vuln/detail/{quote(cve_id.upper())}"


def to_api(cve_id: str) -> str:
    """Get api url to CVE"""
    return f"https://services.nvd.nist.gov/rest/json/cve/1.0/{quote(cve_id.upper())}"


def get_cve_raw_data(cve_id: str) -> dict:
    """Get CVE data from nist API

    :raises EzeNetworkingError: on networking error or json decoding error
    """
    api_url = to_api(cve_id)
    raw_data = request_json(api_url)
    cve_data = py_.get(raw_data, "result.CVE_Items[0]", None)
    if not cve_data:
        raise EzeNetworkingError(f"unable to find CVE '{cve_id}' data")
    return cve_data


def _get_cve_en_summary(cvss_report: dict) -> str:
    """Get english data from cvss data, fallback to first non english"""
    texts = py_.get(cvss_report, "cve.description.description_data", [])
    en_text = py_.find(texts, {"lang": "en"})
    if en_text:
        return en_text["value"]
    if len(texts) > 0:
        return texts[0]["value"]
    return None


def get_cve_data(cve_id) -> dict:
    """
    create small fragment of CVE for usage

    :raises EzeNetworkingError: on networking error or json decoding error
    """
    cvss_report = get_cve_raw_data(cve_id)
    severity = None
    vector = None
    rating = None
    if py_.get(cvss_report, "impact.baseMetricV3"):
        severity = py_.get(cvss_report, "impact.baseMetricV3.cvssV3.baseSeverity", None)
        vector = py_.get(cvss_report, "impact.baseMetricV3.cvssV3.vectorString", None)
        rating = py_.get(cvss_report, "impact.baseMetricV3.cvssV3.baseScore", None)
    elif py_.get(cvss_report, "impact.baseMetricV2"):
        severity = py_.get(cvss_report, "impact.baseMetricV2.severity", None)
        vector = py_.get(cvss_report, "impact.baseMetricV2.cvssV2.vectorString", None)
        rating = py_.get(cvss_report, "impact.baseMetricV2.cvssV2.baseScore", None)
    summary = _get_cve_en_summary(cvss_report)
    return {
        "summary": summary,
        "severity": severity,
        "vector": vector,
        "rating": rating,
        "url": to_url(cve_id),
        "id": cve_id,
        "advisory_modified": py_.get(cvss_report, "lastModifiedDate", None),
        "advisory_created": py_.get(cvss_report, "publishedDate", None),
    }
