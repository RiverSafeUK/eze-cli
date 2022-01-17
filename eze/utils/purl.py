"""
Helper class for manipulating purl, which are used in cyclonedx to describe components
https://github.com/package-url/purl-spec
"""

import re
from urllib.parse import unquote

from pydash import py_

PURL_RE = re.compile("^([^:]+):([^/]+)(\/([^@?#]+))?\/([^?@#]+)(@([^?#]+))?(\?([^?#]+))?(#([^?#]+))?", re.IGNORECASE)


class PurlBreakdown:
    """Wrapper around purl breakdown to provide easy code typing"""

    def __init__(self, vo: dict):
        """constructor"""
        self.scheme: str = py_.get(vo, "scheme")
        self.type: str = py_.get(vo, "type")
        self.namespace: str = py_.get(vo, "namespace")
        self.name: str = py_.get(vo, "name")
        self.version: str = py_.get(vo, "version")
        self.qualifiers: str = py_.get(vo, "qualifiers")
        self.subpath: str = py_.get(vo, "subpath")
        self.full_name: str = py_.get(vo, "full_name")


def safe_unquote(html_fragment):
    """wrapped unquote, with None check"""
    return unquote(html_fragment) if html_fragment else None


def purl_to_components(purl: str) -> PurlBreakdown:
    """
    split purl into it's components
    aka scheme:type/namespace/name@version?qualifiers#subpath
    """
    purl_match = re.match(PURL_RE, purl)
    if not purl_match:
        return None
    match_groups = purl_match.groups()
    breakdown: PurlBreakdown = PurlBreakdown(
        {
            "scheme": safe_unquote(match_groups[0]),
            "type": safe_unquote(match_groups[1]),
            "namespace": safe_unquote(match_groups[3]),
            "name": safe_unquote(match_groups[4]),
            "version": safe_unquote(match_groups[6]),
            "qualifiers": safe_unquote(match_groups[8]),
            "subpath": safe_unquote(match_groups[10]),
        }
    )
    breakdown.full_name = f"{breakdown.namespace}/{breakdown.name}" if breakdown.namespace else breakdown.name
    return breakdown
