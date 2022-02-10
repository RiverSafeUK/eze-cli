"""
Helper functions for osv vulnerability reports

@see https://osv.dev/list
@see https://osv.dev/docs/
"""
from enum import Enum

import re

from eze.core.enums import Vulnerability, VulnerabilityType, VulnerabilitySeverityEnum

from eze.utils.io import pretty_print_json
from pydash import py_

from eze.utils.http import request_json
from eze.utils.error import EzeError
from eze.utils.cve import severity_rating

LICENSE_CLASSIFIER = re.compile("license :: ", re.IGNORECASE)
CVE_CLASSIFIER = re.compile("^CVE-[0-9-]+$", re.IGNORECASE)


class OsvEcosystem(Enum):
    """Enum for Ecosystems supported by """

    DWF = "DWF"  # Global Security Database DWF: https://github.com/cloudsecurityalliance/gsd-database/
    GSD = "GSD"  # Global Security Database: https://github.com/cloudsecurityalliance/gsd-database/
    Go = "Go"  # Go: golang.org
    Javascript = "Javascript"
    Linux = "Linux"  # Global Security Database Linux: https://github.com/cloudsecurityalliance/gsd-database/
    Maven = "Maven"  # Java Maven https://maven.apache.org/
    NuGet = "NuGet"  # .NET NuGet https://www.nuget.org/
    OSSFuzz = "OSS-Fuzz"
    Packagist = "Packagist"  # PHP Composer Packagist https://packagist.org/
    PyPI = "PyPI"  # Python PyPI: https://github.com/pypa/advisory-db
    RubyGems = "RubyGems"  # Ruby Gems: https://rubygems.org/
    UVI = "UVI"
    cratesio = "crates.io"  # Rust crates.io: https://crates.io/
    npm = "npm"  # Node npm: https://www.npmjs.com/


class OsvPackageVO:
    """Wrapper around osv data to provide easy code typing"""

    def __init__(self, vo: dict):
        """constructor"""
        self.package_name: str = py_.get(vo, "package_name", None)
        self.package_version: str = py_.get(vo, "package_version", None)
        self.vulnerabilities: str = py_.get(vo, "vulnerabilities", [])
        self.warnings: str = py_.get(vo, "warnings", [])


def from_maven_package_to_osv_id(package_name: str) -> str:
    """normalise x.x.x/xxx into x.x.x.xxx """
    package_name = re.sub("[/]([a-zA-Z0-9.-]+$)", '.\g<1>', package_name)
    return package_name


def get_affected_package(raw_vulnerability: dict, package_name: str) -> str:
    """collected fixed versions"""
    affected_packages = py_.get(raw_vulnerability, 'affected', [])
    packages = list(filter(lambda x: py_.get(x, 'package.name') == package_name, affected_packages))
    if len(packages) == 0:
        return None
    return packages[0]


def get_recommendation(raw_vulnerability: dict, package_name: str) -> str:
    """collected fixed versions
    affected(filtered by name=package_name).ranges[index type=ECOSYSTEM].events(filtered by fixed=xxx)
    """
    package = get_affected_package(raw_vulnerability, package_name)
    if not package:
        return None
    containers = py_.get(package, 'ranges', [])
    ecosystem_containers = list(filter(lambda container: py_.get(container, "type") == "ECOSYSTEM", containers))
    if not ecosystem_containers:
        return None
    ecosystem_events = py_.get(ecosystem_containers, '[0].events', [])
    filtered_events = list(filter(lambda event: 'fixed' in event, ecosystem_events))
    fix_versions = list(map(lambda event: event['fixed'], filtered_events))
    if len(fix_versions) == 0:
        return None
    return f"Update package to non-vulnerable version {','.join(fix_versions)}"


def add_identifier(identifiers: dict, id: str) -> None:
    """add identifier such as CWE-222 to list"""
    matches = re.match("^([^-]+)-(.*)$", id)
    if not matches:
        identifiers[id] = id
        return
    identifier_group = matches.group(1)
    identifiers[identifier_group] = id


def get_severity(raw_vulnerability: dict, package_name: str) -> str:
    """add identifier such as CWE-222 to list"""
    package: dict = get_affected_package(raw_vulnerability, package_name)
    cvss_score = py_.get(package, 'database_specific.cvss.score')
    cvss_vector = py_.get(package, 'database_specific.cvss.vectorString')
    if not cvss_score or not cvss_vector:
        return VulnerabilitySeverityEnum.high.value
    if re.match("^CVSS:3", cvss_vector):
        return severity_rating(cvss_score, "CVSS3")
    return severity_rating(cvss_score, "CVSS2")


def convert_vulnerability(raw_vulnerability: dict, package_name: str, package_version: str, project_name: str):
    primary_id: str = py_.get(raw_vulnerability, "id")

    # Populate identifiers
    identifiers: dict = {}
    add_identifier(identifiers, primary_id)
    for secondary_id in py_.get(raw_vulnerability, 'aliases', []):
        add_identifier(identifiers, secondary_id)

    package: dict = get_affected_package(raw_vulnerability, package_name)
    cwes: list = py_.get(package, 'database_specific.cwes', [])
    for cwe in cwes:
        cwe_id: str = py_.get(cwe, 'cweId')
        add_identifier(identifiers, cwe_id)

    return Vulnerability(
        {
            "name": package_name,
            "version": package_version,
            "overview": py_.get(raw_vulnerability, "summary", primary_id),
            "identifiers": identifiers,
            "vulnerability_type": VulnerabilityType.dependency.name,
            "recommendation": get_recommendation(raw_vulnerability, package_name),
            "severity": get_severity(raw_vulnerability, package_name),
            "is_ignored": False,
            "file_location": {"path": project_name, "line": 1},
        }
    )


def get_osv_package_data(ecosystem: str, package_name: str, package_version: str, project_name: str) -> OsvPackageVO:
    """
    download and extract vulnerability information for package

    @see https://osv.dev/docs/#operation/OSV_QueryAffected
    """
    pypi_url: str = f"https://api.osv.dev/v1/query"
    warnings = []
    osv_data: dict = {}
    body: dict = {
        "version": package_version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    try:
        request_data = pretty_print_json(body).encode("utf-8")
        osv_data = request_json(pypi_url, request_data)
    except EzeError as error:
        warnings.append(f"unable to get osv data for {ecosystem}:{package_name}:{package_version}, Error: {error}")

    vulnerabilities = list(
        map(
            lambda raw_vulnerability: convert_vulnerability(
                raw_vulnerability, package_name, package_version, project_name
            ),
            py_.get(osv_data, "vulns", []),
        )
    )

    return OsvPackageVO(
        {
            "package_name": package_name,
            "package_version": package_version,
            "vulnerabilities": vulnerabilities,
            "warnings": warnings,
        }
    )
