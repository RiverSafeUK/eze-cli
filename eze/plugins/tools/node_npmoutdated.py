"""NpmAudit tool class"""
import shlex

import semantic_version
from pydash import py_

from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum, ToolType, SourceType
from eze.core.tool import (
    ToolMeta,
    Vulnerability,
    ScanResult,
)
from eze.utils.cli import build_cli_command, extract_cmd_version, run_async_cmd
from eze.utils.io import create_tempfile_path, write_text, parse_json
from eze.utils.semvar import get_severity, get_recommendation
from eze.utils.language.node import install_node_dependencies


class NpmOutdatedTool(ToolMeta):
    """NpmOutdated Node tool class"""

    TOOL_NAME: str = "node-npmoutdated"
    TOOL_TYPE: ToolType = ToolType.SCA
    SOURCE_SUPPORT: list = [SourceType.NODE]
    SHORT_DESCRIPTION: str = "opensource node outdated dependency scanner"
    INSTALL_HELP: str = """In most cases all that is required to install node and npm (version 6+)
npm --version"""
    MORE_INFO: str = """https://docs.npmjs.com/cli/v6/commands/npm-outdated
https://docs.npmjs.com/downloading-and-installing-node-js-and-npm
"""
    EZE_CONFIG: dict = {
        "SOURCE": {
            "type": str,
            "default": None,
            "help_text": """folder where node package.json, will default to folder eze ran from""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-npmoutdated-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-npmoutdated-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
        "NEWER_MAJOR_SEMVERSION_SEVERITY": {
            "type": str,
            "default": VulnerabilitySeverityEnum.medium.name,
            "help_text": """severity of vulnerabilty to raise, if new major version available of a package""",
        },
        "NEWER_MINOR_SEMVERSION_SEVERITY": {
            "type": str,
            "default": VulnerabilitySeverityEnum.low.name,
            "help_text": """severity of vulnerabilty to raise, if new minor version available of a package""",
        },
        "NEWER_PATCH_SEMVERSION_SEVERITY": {
            "type": str,
            "default": VulnerabilitySeverityEnum.none.name,
            "help_text": """severity of vulnerabilty to raise, if new patch version available of a package""",
        },
    }
    # https://github.com/npm/cli/blob/latest/LICENSE
    LICENSE: str = """NPM"""

    TOOL_LANGUAGE = "node"
    DEFAULT_SEVERITY = VulnerabilitySeverityEnum.high.name

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            "BASE_COMMAND": shlex.split("npm outdated --json"),
            # eze config fields -> flags
            "FLAGS": {},
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        version = extract_cmd_version(["npm", "--version"])
        # npm outdated only available in version 6 and above
        try:
            version6_or_above = semantic_version.SimpleSpec(">=6")
            parsed_version = semantic_version.Version(version)
            if not version6_or_above.match(parsed_version):
                return ""
        except ValueError:
            return version
        return version

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """
        # TODO: add support for multiple package.json's in non base folder in (self.config["SOURCE"])
        install_node_dependencies()
        command_str = build_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config)
        completed_process = await run_async_cmd(command_str, True)
        report_text = completed_process.stdout

        write_text(self.config["REPORT_FILE"], report_text)
        parsed_json = parse_json(report_text)
        report = self.parse_report(parsed_json)
        return report

    def parse_report(self, parsed_json: list) -> ScanResult:
        """convert report json into ScanResult"""

        warnings = []
        vulnerabilities_list = []
        for outdated_package in parsed_json:
            outdated_module = parsed_json[outdated_package]

            current_installed_version = py_.get(outdated_module, "current")
            if not current_installed_version:
                warnings.append(
                    f"{outdated_package}: package not locally installed, detecting outdated status from wanted version, fix with `npm install`"
                )
            installed_version = current_installed_version or outdated_module["wanted"]
            latest_version = outdated_module["latest"]
            semver_severity = get_severity(installed_version, latest_version, self.config)
            semver_recommendation = get_recommendation(outdated_package, installed_version, latest_version)

            vulnerability_vo = {
                "vulnerability_type": VulnerabilityType.dependency.name,
                "name": outdated_package,
                "version": installed_version,
                "overview": "",
                "recommendation": semver_recommendation,
                "language": self.TOOL_LANGUAGE,
                "severity": semver_severity,
                "identifiers": {},
                "metadata": None,
                "file_location": None,
            }
            vulnerabilities_list.append(Vulnerability(vulnerability_vo))

        report = ScanResult(
            {
                "tool": self.TOOL_NAME,
                "vulnerabilities": vulnerabilities_list,
                "warnings": warnings,
            }
        )
        return report
