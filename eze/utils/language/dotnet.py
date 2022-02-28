import re
import shlex

from pydash import py_

from eze.utils.data.osv import get_osv_id_data

from eze.core.enums import Vulnerability, VulnerabilitySeverityEnum, VulnerabilityType
from eze.utils.cli.run import run_async_cmd


class DeprecatedPackage:
    def __init__(self, vo: list):
        self.package = vo[0]
        self.request_version = vo[1]
        self.installed_version = vo[2]
        self.reason = vo[3]
        self.alternative = vo[4]


class VulnerablePackage:
    def __init__(self, vo: list):
        self.package = vo[0]
        self.request_version = vo[1]
        self.installed_version = vo[2]
        self.severity = vo[3]
        self.advisory_url = vo[4]
        advisory_id_matches = re.compile(r".*[/](.*)$", re.ASCII).match(self.advisory_url)
        self.advisory_id = advisory_id_matches.group(1) if advisory_id_matches else None


class DotnetPackage:
    def __init__(self, vo: list, is_transitive: bool):
        self.is_transitive = is_transitive
        self.package = vo[0]
        if len(vo) == 2:
            self.installed_version = vo[1]
        if len(vo) == 4:
            self.request_version = vo[1]
            self.installed_version = vo[3]


def extract_deprecated_packages(stdout: str) -> list:
    """
    extract deprecated packages from dotnet output
    TODO: upgrade to --json dotnet once available
    """
    deprecated_package_re = re.compile(r"^[ ]+>[ ]+([^ ]+)[ ]+([^ ]+)[ ]+([^ ]+)[ ]+([^ ]+)[ ]+(.+)", re.ASCII)
    stdout_lines = stdout.split("\n")
    deprecated_packages: list = []
    for stdout_line in stdout_lines:
        matches = deprecated_package_re.match(stdout_line)
        if not matches:
            continue
        deprecated_packages.append(DeprecatedPackage(matches.groups()))
    return deprecated_packages


async def get_deprecated_packages(project_folder: str) -> list:
    """
    use dotnet to get list of deprecated packages
    @see https://www.nuget.org/packages?q=deprecated
    """
    completed_process = await run_async_cmd(shlex.split("dotnet list package --deprecated"), cwd=project_folder)
    return list(
        map(
            lambda deprecated_package: Vulnerability(
                {
                    "name": deprecated_package.package,
                    "version": deprecated_package.installed_version,
                    "overview": f"'{deprecated_package.package}' is deprecated",
                    "vulnerability_type": VulnerabilityType.dependency.name,
                    "recommendation": f"recommended migrate to {deprecated_package.alternative}"
                    if deprecated_package.alternative
                    else None,
                    "severity": VulnerabilitySeverityEnum.medium.name,
                    "file_location": {"path": project_folder, "line": 1},
                }
            ),
            extract_deprecated_packages(completed_process.stdout),
        )
    )


def extract_vulnerable_packages(stdout: str) -> list:
    """
    extract deprecated packages from dotnet output
    TODO: upgrade to --json dotnet once available
    """
    deprecated_package_re = re.compile(r"^[ ]+>[ ]+([^ ]+)[ ]+([^ ]+)[ ]+([^ ]+)[ ]+([^ ]+)[ ]+(.+)", re.ASCII)
    stdout_lines = stdout.split("\n")
    deprecated_packages: list = []
    for stdout_line in stdout_lines:
        matches = deprecated_package_re.match(stdout_line)
        if not matches:
            continue
        deprecated_packages.append(VulnerablePackage(matches.groups()))
    return deprecated_packages


async def get_vulnerable_packages(project_folder: str) -> list:
    """
    use dotnet to get list of deprecated packages
    @see https://www.nuget.org/packages?q=deprecated
    """
    completed_process = await run_async_cmd(shlex.split("dotnet list package --vulnerable"), cwd=project_folder)
    vulnerable_packages = extract_vulnerable_packages(completed_process.stdout)
    vp: VulnerablePackage
    vulnerabilities = []
    for vp in vulnerable_packages:
        if vp.advisory_id:
            vulnerabilities.append(get_osv_id_data(vp.advisory_id, vp.package, vp.installed_version, project_folder))
        else:
            vulnerabilities.append(
                Vulnerability(
                    {
                        "name": vp.package,
                        "version": vp.installed_version,
                        "overview": f"'{vp.package}' has {vp.severity.lower()} vulnerability {vp.advisory_url}",
                        "vulnerability_type": VulnerabilityType.dependency.name,
                        "recommendation": None,
                        "severity": vp.severity.lower(),
                        "file_location": {"path": project_folder, "line": 1},
                    }
                )
            )
    return vulnerabilities


def _extract_transitive_packages(stdout: str, is_transitive: bool) -> dict:
    """
    extract packages from dotnet output, as indexed
    TODO: upgrade to --json dotnet once available
    """
    package_re = re.compile(r"^[ ]+>[ ]+([^ ]+)[ ]+([^ ]+)([ ]+([^ ]+))?", re.ASCII)
    stdout_lines = stdout.split("\n")
    packages: dict = {}
    for stdout_line in stdout_lines:
        matches = package_re.match(stdout_line)
        if not matches:
            continue
        package = DotnetPackage(matches.groups(), is_transitive)
        packages[package.package] = package
    return packages


def extract_transitive_packages(stdout: str) -> dict:
    """
    extract top level abd transitive packages from dotnet output, as indexed
    TODO: upgrade to --json dotnet once available
    """
    stdouts: list = stdout.split("Transitive Package")
    top_level_stdout: str = py_.get(stdouts, "[0]", "")
    transitive_stdout: str = py_.get(stdouts, "[1]", "")
    return {
        "top_level": _extract_transitive_packages(top_level_stdout, False),
        "transitive": _extract_transitive_packages(transitive_stdout, True),
    }


async def annotate_transitive_licenses(sbom: dict, project_folder: str) -> dict:
    """adding annotations to licenses which are not top-level"""
    completed_process = await run_async_cmd(shlex.split("dotnet list package --vulnerable"), cwd=project_folder)
    packages = extract_transitive_packages(completed_process.stdout)
    for component in sbom["components"]:
        component_name = component["name"]
        is_transitive = component_name in packages["top_level"]
        is_not_transitive = component_name in packages["transitive"]
        if is_transitive:
            py_.set(component, "properties.transitive", False)
        elif is_not_transitive:
            py_.set(component, "properties.transitive", True)
    return packages
