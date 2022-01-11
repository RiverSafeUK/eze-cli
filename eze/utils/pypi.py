"""Helper functions for python based tools"""

from urllib.parse import quote

import re
from pydash import py_

from eze.core.enums import Vulnerability, VulnerabilitySeverityEnum, VulnerabilityType
from eze.utils.http import request_json

LICENSE_CLASSIFIER = re.compile("license :: ", re.IGNORECASE)
CVE_CLASSIFIER = re.compile("^CVE-[0-9-]+$", re.IGNORECASE)


def filter_license_classifiers(classifiers):
    """filter list of pypi classifiers for licenses only"""
    license_classifiers = list(filter(LICENSE_CLASSIFIER.match, classifiers)) if classifiers else []
    return license_classifiers


def get_recommendation(vulnerability):
    """filter list of pypi classifiers for licenses only"""
    fix_versions = py_.get(vulnerability, "fixed_in")
    if len(fix_versions) == 0:
        return None
    return f"Update package to non-vulnerable version {','.join(fix_versions)}"


def convert_vulnerability(vulnerability) -> Vulnerability:
    aliases = py_.get(vulnerability, "aliases", [])
    cves = list(filter(LICENSE_CLASSIFIER.match, aliases)) if aliases else []
    identifiers = {"PYSEC": py_.get(vulnerability, "id")}
    if len(cves) > 0:
        identifiers["CVE"] = cves[0]

    return Vulnerability(
        {
            "name": py_.get(vulnerability, "details"),
            "identifiers": identifiers,
            "vulnerability_type": VulnerabilityType.dependency.name,
            "recommendation": get_recommendation(vulnerability),
            "severity": VulnerabilitySeverityEnum.medium.name,
            "is_ignored": False,
        }
    )


def get_pypi_package_data(package_name: str, package_version: str) -> dict:
    """
    download and extract license and vulnerability information for package

    @see https://github.com/pypa/advisory-db
    @see https://warehouse.pypa.io/api-reference/json.html
    """
    pypi_url: str = f"https://pypi.org/pypi/{quote(package_name)}/{quote(package_version)}/json"
    package_metadata: dict = request_json(pypi_url)

    classifiers = py_.get(package_metadata, "info.classifiers", [])
    vulnerabilities = map(convert_vulnerability, py_.get(package_metadata, "vulnerabilities", []))

    return {"license": filter_license_classifiers(classifiers), "vulnerabilities": vulnerabilities}
