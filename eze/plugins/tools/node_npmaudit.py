"""NpmAudit tool class"""
import shlex

import semantic_version
from eze.utils.log import log_debug
from pydash import py_

from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum, ToolType, SourceType, Vulnerability
from eze.core.tool import (
    ToolMeta,
    ScanResult,
)
from eze.utils.cli.run import build_cli_command, run_async_cmd
from eze.utils.io.file import create_tempfile_path, write_text, parse_json
from eze.utils.language.node import install_npm_in_path
from eze.utils.io.file_scanner import find_files_by_name
from pathlib import Path


class NpmAuditTool(ToolMeta):
    """NpmAudit Node tool class"""

    TOOL_NAME: str = "node-npmaudit"
    TOOL_URL: str = "https://docs.npmjs.com/cli/v6/commands/npm-audit"
    TOOL_TYPE: ToolType = ToolType.SCA
    SOURCE_SUPPORT: list = [SourceType.NODE]
    SHORT_DESCRIPTION: str = "opensource node SCA scanner"
    INSTALL_HELP: str = """In most cases all that is required to install node and npm (version 6+)
npm --version"""
    MORE_INFO: str = """https://docs.npmjs.com/cli/v6/commands/npm-audit
https://docs.npmjs.com/downloading-and-installing-node-js-and-npm
"""
    EZE_CONFIG: dict = {
        "INCLUDE_DEV": {
            "type": bool,
            "default": False,
            "help_text": "Include development dependencies from the SCA, if false adds '--only=prod' flag to ignore devDependencies",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-npmaudit-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-npmaudit-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
    }
    # https://github.com/npm/cli/blob/latest/LICENSE
    LICENSE: str = """NPM"""
    VERSION_CHECK: dict = {"FROM_EXE": "npm --version", "CONDITION": ">=6"}

    TOOL_LANGUAGE = "node"
    DEFAULT_SEVERITY = VulnerabilitySeverityEnum.high.name

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            "BASE_COMMAND": shlex.split("npm audit --json"),
            # eze config fields -> flags
            "SHORT_FLAGS": {"_ONLY_PROD": "--only=prod"},
        }
    }

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """
        vulnerabilities_list = []
        npm_package_jsons = find_files_by_name("^package.json$")
        for npm_package in npm_package_jsons:
            log_debug(f"run 'npm audit' on {npm_package}")
            npm_project = Path(npm_package).parent
            npm_project_fullpath = Path.joinpath(Path.cwd(), npm_project)
            await install_npm_in_path(npm_project)
            command_str = build_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config)
            completed_process = await run_async_cmd(command_str, True, cwd=npm_project_fullpath)
            report_text = completed_process.stdout
            write_text(self.config["REPORT_FILE"], report_text)
            parsed_json = parse_json(report_text)
            vulnerabilities = self.parse_report(parsed_json, npm_package)
            vulnerabilities_list.extend(vulnerabilities)

        report = ScanResult(
            {
                "tool": self.TOOL_NAME,
                "vulnerabilities": vulnerabilities_list,
                "warnings": [],
            }
        )

        return report

    def parse_report(self, parsed_json: dict, npm_package: str = None) -> list:
        """convert report json into ScanResult"""
        v6_vulnerability_container = py_.get(parsed_json, "advisories")
        # v6 npm audit
        if v6_vulnerability_container:
            return self.parse_npm_v6_report(parsed_json, npm_package)

        # v7 npm audit
        # https://blog.npmjs.org/post/626173315965468672/npm-v7-series-beta-release-and-semver-major
        return self.parse_npm_v7_report(parsed_json, npm_package)

    def create_recommendation_v7(self, vulnerability: dict):
        """convert vulnerability dict into recommendation"""
        fix_available = vulnerability["fixAvailable"]
        if not fix_available:
            return "no fix available"

        recommendation = "fix available via `npm audit fix --force`"
        if fix_available is True:
            return recommendation

        recommendation += f"\nWill install {fix_available['name']}@{fix_available['version']}"

        if fix_available["isSemVerMajor"] is True:
            recommendation += ", which is a breaking change"

        return recommendation

    def create_path_v7(self, vulnerability: dict) -> str:
        """extract the path from the vulnerability"""
        # detected module from vulnerability details
        module_name = py_.get(vulnerability, "via[0].name", False) or py_.get(vulnerability, "name")

        # create path
        module_path = ""
        for parent_module in vulnerability["effects"]:
            module_path += f"{parent_module}>"

        # pull it all together
        path = f"{module_path}{module_name}"

        return path

    def create_version_v7(self, vulnerability: dict) -> str:
        """extract the version from the vulnerability"""
        module_version = py_.get(vulnerability, "via[0].range", False) or py_.get(vulnerability, "range")

        return module_version

    def create_description_v7(self, vulnerability: dict):
        """extract the description from the vulnerability"""
        # detected module from vulnerability details
        module_version = self.create_version_v7(vulnerability)

        # create path
        module_path = self.create_path_v7(vulnerability)

        # if advisory not present, it's a insecure dependency issue
        advisory_title = py_.get(vulnerability, "via[0].title", "")
        if not advisory_title:
            advisory_title = "has insecure dependency "
            advisory_title += ">".join(reversed(vulnerability["via"]))

        # pull it all together
        path = f"{module_path}({module_version})"

        if advisory_title:
            path += f": {advisory_title}"

        return path

    def parse_npm_v7_report(self, parsed_json: dict, npm_package: str) -> list:
        """Parses newer v7 npm audit format"""
        # WARNING: npm v7 report format doesn't look complete
        #
        # wouldn't be surprised if there are future breaking changes to the format,
        # at a glance the v2 reports looks less mature to v1 reports
        # and looks like there are some quality and accuracy issues
        # ("via" array doesn't always seem correct for complex dependency trees)
        #
        # Excellent commentary : https://uko.codes/dealing-with-npm-v7-audit-changes
        vulnerabilities = py_.get(parsed_json, "vulnerabilities", None)
        vulnerabilities_list = []

        if vulnerabilities:
            for vulnerability_key in vulnerabilities:
                vulnerability = vulnerabilities[vulnerability_key]

                name: str = self.create_path_v7(vulnerability)
                version: str = self.create_version_v7(vulnerability)
                description: str = self.create_description_v7(vulnerability)
                recommendation: str = self.create_recommendation_v7(vulnerability)

                references = []
                npm_reference = py_.get(vulnerability, "via[0].url", False)
                if npm_reference:
                    references.append(npm_reference)

                vulnerability_vo = {
                    "vulnerability_type": VulnerabilityType.dependency.name,
                    "name": name,
                    "version": version,
                    "overview": description,
                    "recommendation": recommendation,
                    "severity": vulnerability["severity"],
                    "identifiers": {},
                    "references": references,
                    "metadata": None,
                    "file_location": {"path": npm_package, "line": 1},
                }

                # WARNING: AB-524: limitation, for now just showing first advisory
                advisory_source = py_.get(vulnerability, "via[0].source", False)
                if advisory_source:
                    vulnerability_vo["identifiers"]["npm"] = advisory_source

                vulnerabilities_list.append(Vulnerability(vulnerability_vo))

        return vulnerabilities_list

    def parse_npm_v6_report(self, parsed_json: dict, npm_package: str) -> list:
        """Parses newer v6 npm audit format"""
        advisories = parsed_json["advisories"]
        vulnerabilities_list = []

        for advisory_key in advisories:
            advisory = advisories[advisory_key]
            module_name = advisory["module_name"]

            first_path = py_.get(advisory, "findings[0].paths[0]", False)
            version = py_.get(advisory, "findings[0].version", None)
            if first_path:
                module_name = f"{first_path}({version})"

            references = []
            npm_reference = py_.get(advisory, "url")
            if npm_reference:
                references.append(npm_reference)

            vulnerability_vo = {
                "vulnerability_type": VulnerabilityType.dependency.name,
                "name": f"{module_name}: {advisory['title']}",
                "version": version,
                "overview": advisory["overview"],
                "recommendation": advisory["recommendation"],
                "severity": advisory["severity"],
                "identifiers": {},
                "references": references,
                "metadata": None,
                "file_location": {"path": npm_package, "line": 1},
            }
            cwe = py_.get(advisory, "cwe")
            if cwe:
                vulnerability_vo["identifiers"]["cwe"] = cwe

            # WARNING: AB-524: limitation, for know just showing first CVE
            cves = py_.get(advisory, "cves")
            if cves and len(cves) > 0:
                vulnerability_vo["identifiers"]["cve"] = cves[0]

            vulnerabilities_list.append(Vulnerability(vulnerability_vo))

        return vulnerabilities_list

    def _parse_config(self, eze_config: dict) -> dict:
        """take raw config dict and normalise values"""
        parsed_config = super()._parse_config(eze_config)

        # ADDITION PARSING: invert INCLUDE_DEV into _ONLY_PROD(--only-prod) flag
        parsed_config["_ONLY_PROD"] = not parsed_config["INCLUDE_DEV"]

        return parsed_config
