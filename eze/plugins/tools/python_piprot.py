"""Piprot Python tool class"""

import re
import shlex

from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum, ToolType, SourceType, Vulnerability
from eze.core.tool import (
    ToolMeta,
    ScanResult,
)
from eze.utils.cli import detect_pip_executable_version, run_async_cli_command
from eze.utils.io import create_tempfile_path, write_text
from eze.utils.semvar import get_severity, get_recommendation
from eze.utils.file_scanner import find_files_by_name


class PiprotTool(ToolMeta):
    """Python Piprot tool class"""

    TOOL_NAME: str = "python-piprot"
    TOOL_URL: str = "https://pypi.org/project/piprot/"
    TOOL_TYPE: ToolType = ToolType.SCA
    SOURCE_SUPPORT: list = [SourceType.PYTHON]
    SHORT_DESCRIPTION: str = "opensource python outdated dependency scanner"
    INSTALL_HELP: str = """In most cases all that is required to install piprot is python and pip install

pip install piprot
piprot -h"""
    MORE_INFO: str = """https://github.com/sesh/piprot

Piprot is a tool to ensure your dependencies aren't old and out of date
this is important as old dependencies won't necessarily be actively supported
and can contain hidden vulnerabilities 

There are two types of operation for this plugin
- severity by age
- severity by semver

Ps though piprot is technicially no longer supported by it's developer but it's still an useful excellent tool
until "pip list --outdated" takes a requirements file as a input
https://github.com/pypa/pip/issues/3314

Common Gotchas
===========================
Pip Freezing

A Piprot expects exact version numbers. Therefore requirements.txt must be frozen. 

This can be accomplished via:

$ pip freeze > requirements.txt
"""
    # https://github.com/sesh/piprot/blob/master/LICENCE.txt
    LICENSE: str = """MIT"""
    EZE_CONFIG: dict = {
        "REQUIREMENTS_FILES": {
            "type": list,
            "default": [],
            "help_text": """surplus custom requirements.txt file
any requirements files named requirements.txt or requirements-dev.txt will be automatically collected
gotcha: make sure it's a frozen version of the pip requirements""",
            "help_example": "[custom-requirements.txt]",
        },
        "HIGH_SEVERITY_AGE_THRESHOLD": {
            "type": int,
            "default": 1095,
            "help_text": """number of days before a out of date dependency is moved to High Risk
default 1095 (three years)""",
        },
        "MEDIUM_SEVERITY_AGE_THRESHOLD": {
            "type": int,
            "default": 730,
            "help_text": """number of days before a out of date dependency is moved to Medium Risk
default 730 (two years)""",
        },
        "LOW_SEVERITY_AGE_THRESHOLD": {
            "type": int,
            "default": 182,
            "help_text": """number of days before a out of date dependency is moved to Low Risk
default is 182 (half a year)""",
        },
        #
        "NEWER_MAJOR_SEMVERSION_SEVERITY": {
            "type": str,
            "default": VulnerabilitySeverityEnum.high.name,
            "help_text": """severity if major version available, default to high""",
        },
        "NEWER_MINOR_SEMVERSION_SEVERITY": {
            "type": str,
            "default": VulnerabilitySeverityEnum.medium.name,
            "help_text": """severity if minor version available, default to medium""",
        },
        "NEWER_PATCH_SEMVERSION_SEVERITY": {
            "type": str,
            "default": VulnerabilitySeverityEnum.low.name,
            "help_text": """severity if patch version available, default to low""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-piprot-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-piprot-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
    }

    TOOL_LANGUAGE = "python"
    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": shlex.split("piprot -o"),
            "ARGUMENTS": ["COMPILED_REQUIREMENTS_FILES"],
            # eze config fields -> flags
            "FLAGS": {},
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        return detect_pip_executable_version("piprot", "piprot")

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """
        # TODO: migrate from piprot, and implement directly into cyclonedx plugin (to match new SCA from pypi)

        requirements_files = find_files_by_name("requirements.txt")
        requirements_files.extend(find_files_by_name("requirements-dev.txt"))
        requirements_files.extend(self.config["REQUIREMENTS_FILES"])
        warnings_list = []


        poetry_files = find_files_by_name("poetry.lock")
        if len(poetry_files):
            warnings_list.append(f"piprot does not support poetry files, not scanned: {','.join(poetry_files)}")

        piplock_files = find_files_by_name("Pipfile.lock")
        if len(piplock_files):
            warnings_list.append(f"piprot does not support piplock files, not scanned: {','.join(piplock_files)}")

        if not len(requirements_files):
            warnings_list.append("piprot not ran, no python requirements files found")
            return ScanResult(
                {
                    "tool": self.TOOL_NAME,
                    "warnings": warnings_list,
                })

        scan_config = {
            "COMPILED_REQUIREMENTS_FILES": requirements_files
        }
        scan_config = {**scan_config, **self.config.copy()}
        completed_process = await run_async_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], scan_config, self.TOOL_NAME)
        report_text = completed_process.stdout
        write_text(self.config["REPORT_FILE"], report_text)
        report = self.parse_report(report_text)
        if completed_process.stderr:
            warnings_list.append(completed_process.stderr)

        # add all warnings
        report.warnings.extend(warnings_list)
        return report

    def get_recommendation_by_age(
        self, outdated_package: str, installed_version: str, latest_version: str, package_outdated_in_days: int
    ):
        """get recommendation to update a package by number of days out current version is"""
        recommendation = f"{outdated_package} ({installed_version}) {package_outdated_in_days} days out of date. update to a newer version, latest version: {latest_version}"
        return recommendation

    def get_severity_by_age(self, package_outdated_in_days: int):
        """get the severity by number of days out current version is"""
        if (
            self.config["HIGH_SEVERITY_AGE_THRESHOLD"]
            and self.config["HIGH_SEVERITY_AGE_THRESHOLD"] <= package_outdated_in_days
        ):
            return VulnerabilitySeverityEnum.high.name
        if (
            self.config["MEDIUM_SEVERITY_AGE_THRESHOLD"]
            and self.config["MEDIUM_SEVERITY_AGE_THRESHOLD"] <= package_outdated_in_days
        ):
            return VulnerabilitySeverityEnum.medium.name
        if (
            self.config["LOW_SEVERITY_AGE_THRESHOLD"]
            and self.config["LOW_SEVERITY_AGE_THRESHOLD"] <= package_outdated_in_days
        ):
            return VulnerabilitySeverityEnum.medium.name
        return ""

    def parse_report(self, text: str) -> ScanResult:
        """convert report json into ScanResult"""
        report_events = text.split("\n")
        vulnerabilities_list = []
        # [a-zA-Z0-9]+ ([a-zA-Z0-9]+) is [a-zA-Z0-9]+ days out of date. Latest is [a-zA-Z0-9]+
        # aka requests (2.24.0) is 182 days out of date. Latest is 2.25.1
        piprot_re = re.compile(
            "([a-zA-Z0-9.-]+) [(]([a-zA-Z0-9.-]+)[)] is ([a-zA-Z0-9]+) days out of date. Latest is ([a-zA-Z0-9.-]+)"
        )

        for report_event in report_events:
            parts = piprot_re.match(report_event)
            if not parts:
                continue
            outdated_package = parts.group(1)
            installed_version = parts.group(2)
            latest_version = parts.group(4)
            package_outdated_in_days = int(parts.group(3))

            age_severity = self.get_severity_by_age(package_outdated_in_days)
            if age_severity:
                age_recommendation = self.get_recommendation_by_age(
                    outdated_package, installed_version, latest_version, package_outdated_in_days
                )
                vulnerability_raw = {
                    "vulnerability_type": VulnerabilityType.dependency.name,
                    "name": outdated_package,
                    "version": installed_version,
                    "overview": report_event,
                    "recommendation": age_recommendation,
                    "language": self.TOOL_LANGUAGE,
                    "severity": age_severity,
                    "identifiers": {},
                    "metadata": {},
                }
                vulnerability = Vulnerability(vulnerability_raw)
                vulnerabilities_list.append(vulnerability)

            semver_severity = get_severity(installed_version, latest_version, self.config)
            if semver_severity:
                semver_recommendation = get_recommendation(outdated_package, installed_version, latest_version)
                vulnerability_raw = {
                    "vulnerability_type": VulnerabilityType.dependency.name,
                    "name": outdated_package,
                    "version": installed_version,
                    "overview": report_event,
                    "recommendation": semver_recommendation,
                    "language": self.TOOL_LANGUAGE,
                    "severity": semver_severity,
                    "identifiers": {},
                    "metadata": {},
                }
                vulnerability = Vulnerability(vulnerability_raw)
                vulnerabilities_list.append(vulnerability)

        report = ScanResult(
            {
                "tool": self.TOOL_NAME,
                "vulnerabilities": vulnerabilities_list,
            }
        )
        return report
