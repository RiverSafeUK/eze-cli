"""
Helper functions for python pypi vulnerability reports

@see https://github.com/pypa/advisory-db
@see https://warehouse.pypa.io/api-reference/json.html
"""

from urllib.parse import quote

import re

from eze.utils.purl import PurlBreakdown, purl_to_components
from pydash import py_

from eze.core.enums import Vulnerability, VulnerabilitySeverityEnum, VulnerabilityType
from eze.utils.io.http import request_json
from eze.utils.data.cve import get_cve_data
from eze.utils.error import EzeError

LICENSE_CLASSIFIER = re.compile("license :: ", re.IGNORECASE)
CVE_CLASSIFIER = re.compile("^CVE-[0-9-]+$", re.IGNORECASE)


class PypiPackageVO:
    """Wrapper around pypi data to provide easy code typing"""

    def __init__(self, vo: dict):
        """constructor"""
        self.package_name: str = py_.get(vo, "package_name", None)
        self.package_version: str = py_.get(vo, "package_version", None)
        self.licenses: str = py_.get(vo, "licenses", [])
        self.vulnerabilities: str = py_.get(vo, "vulnerabilities", [])
        self.warnings: str = py_.get(vo, "warnings", [])


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


def convert_vulnerability(
    vulnerability: dict, warnings: list, package_name: str, package_version: str, pip_project_file: str
) -> Vulnerability:
    """
    convert pypi vulnerbaility into a Vulnerability object
    will obtain CVE severity
    non CVE vulnerabilities are classified as HIGH"""
    aliases = py_.get(vulnerability, "aliases", [])
    cves = list(filter(CVE_CLASSIFIER.match, aliases)) if aliases else []
    identifiers = {"PYSEC": py_.get(vulnerability, "id")}
    cve_data = None
    if len(cves) > 0:
        cve_id = cves[0]
        identifiers["CVE"] = cve_id
        try:
            cve_data = get_cve_data(cve_id)
        except EzeError as error:
            warnings.append(f"unable to get cve data for {cve_id}, Error: {error}")
    return Vulnerability(
        {
            "name": package_name,
            "version": package_version,
            "overview": cve_data["summary"] if cve_data else py_.get(vulnerability, "details"),
            "identifiers": identifiers,
            "vulnerability_type": VulnerabilityType.dependency.name,
            "recommendation": get_recommendation(vulnerability),
            "severity": cve_data["severity"] if cve_data else VulnerabilitySeverityEnum.high.name,
            "file_location": {"path": pip_project_file, "line": 1},
        }
    )


def get_pypi_package_data(
    package_name: str, package_version: str = None, python_project_file: str = "."
) -> PypiPackageVO:
    """
    download and extract license and vulnerability information for package

    @see https://github.com/pypa/advisory-db
    @see https://warehouse.pypa.io/api-reference/json.html
    """
    pypi_url: str = (
        f"https://pypi.org/pypi/{quote(package_name)}/{quote(package_version)}/json"
        if package_version
        else f"https://pypi.org/pypi/{quote(package_name)}/json"
    )
    warnings = []
    package_metadata: dict = {}
    try:
        package_metadata = request_json(pypi_url)
    except EzeError as error:
        warnings.append(f"unable to get pypi data for {package_name}:{package_version}, Error: {error}")

    classifiers = py_.get(package_metadata, "info.classifiers", [])
    vulnerabilities = list(
        map(
            lambda raw_vulnerability: convert_vulnerability(
                raw_vulnerability, warnings, package_name, package_version, python_project_file
            ),
            py_.get(package_metadata, "vulnerabilities", []),
        )
    )

    return PypiPackageVO(
        {
            "package_name": package_name,
            "package_version": package_version,
            "licenses": filter_license_classifiers(classifiers),
            "vulnerabilities": vulnerabilities,
            "warnings": warnings,
        }
    )


def _sca_component(component: dict, project_name: str) -> list:
    """
    on component dict using pypi data
    - detect warnings/vulnerabilities
    - populate license information
    """
    purl = py_.get(component, "purl")
    purl_breakdown: PurlBreakdown = purl_to_components(purl)
    if not purl_breakdown or purl_breakdown.type != "pypi":
        return [[], []]
    pypi_data: PypiPackageVO = get_pypi_package_data(purl_breakdown.name, purl_breakdown.version, project_name)
    licenses = component.get("licenses", [])
    if len(licenses) == 0:
        for pypi_license in pypi_data.licenses:
            licenses.append({"license": {"name": pypi_license}})
        component["licenses"] = licenses
    return [pypi_data.vulnerabilities, pypi_data.warnings]


def pypi_sca_sboms(cyclonedx_boms: dict) -> list:
    """
    parses dict of cyclonedx sboms
    annotates sboms with license information
    returns the pypi vulnerabilities and warnings
    """
    vulnerabilities: list = []
    warnings: list = []
    for project_name in cyclonedx_boms:
        cyclonedx_bom = cyclonedx_boms[project_name]
        for component in py_.get(cyclonedx_bom, "components", []):
            [pypi_vulnerabilities, pypi_warnings] = _sca_component(component, project_name)
            vulnerabilities.extend(pypi_vulnerabilities)
            warnings.extend(pypi_warnings)
    return [vulnerabilities, warnings]
