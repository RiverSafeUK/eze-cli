"""OWASP dependency-check java tool class to detect vulnerabilities within project dependencies"""

import re
import shlex

from eze.core.enums import VulnerabilityType, ToolType, SourceType, Vulnerability
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli import extract_version_from_maven, run_cli_command
from eze.utils.cve import CVE
from eze.utils.io import create_tempfile_path, load_json, write_json
from eze.utils.error import EzeError


class JavaDependencyCheckTool(ToolMeta):
    """OWASP dependency-check tool class"""

    TOOL_NAME: str = "java-dependencycheck"
    TOOL_TYPE: ToolType = ToolType.SCA
    SOURCE_SUPPORT: list = [SourceType.JAVA]
    SHORT_DESCRIPTION: str = "opensource java SCA tool class"
    INSTALL_HELP: str = """In most cases all that is required is java and mvn installed

https://maven.apache.org/download.cgi

test if installed with

mvn --version
"""
    MORE_INFO: str = """
https://jeremylong.github.io/DependencyCheck/
https://owasp.org/www-project-dependency-check/
https://jeremylong.github.io/DependencyCheck/dependency-check-maven/configuration.html

Tips and Tricks
===========================
You can add suppression file to customise your output
https://jeremylong.github.io/DependencyCheck/general/suppression.html
"""
    # https://github.com/jeremylong/DependencyCheck/blob/main/LICENSE.txt
    LICENSE: str = """Apache-2.0"""
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-java-dependencycheck.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-java-dependencycheck.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
        "MVN_REPORT_FILE": {
            "type": str,
            "default": "target/dependency-check-report.json",
            "help_text": "maven output dependency-check-report.json location, will be loaded, parsed and copied to <REPORT_FILE>",
        },
    }

    TOOL_LANGUAGE = "java"
    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            # https://jeremylong.github.io/DependencyCheck/dependency-check-cli/arguments.html
            "BASE_COMMAND": shlex.split(
                "mvn -Dmaven.test.skip=true clean install org.owasp:dependency-check-maven:check -Dformat=JSON -DprettyPrint"
            )
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        version = extract_version_from_maven("org.owasp:dependency-check-maven")
        return version

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """

        completed_process = run_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME)
        owasp_report = load_json(self.config["MVN_REPORT_FILE"])

        write_json(self.config["REPORT_FILE"], owasp_report)
        report = self.parse_report(owasp_report)
        if completed_process.stderr:
            report.warnings.append(completed_process.stderr)

        return report

    def parse_report(self, parsed_json: dict) -> ScanResult:
        """convert report json into ScanResult"""
        report_events = parsed_json
        vulnerabilities_list = []
        warnings = []

        for dependency in report_events["dependencies"]:
            if "vulnerabilities" not in dependency:
                continue

            [_, pkg_name, pkg_version] = re.split("@|:", remove_backslash(dependency["packages"][0]["id"]))
            for vulnerability in dependency["vulnerabilities"]:

                vulnerable_versions = []
                for vulnerable_software in vulnerability["vulnerableSoftware"]:
                    vulnerable_versions.append(vulnerable_software["software"]["id"].split(":")[5])

                summary = vulnerability["description"]
                cve = CVE.detect_cve(vulnerability["name"])
                cve_data = None
                metadata = {"vulnerability": {"id": vulnerability["name"]}}
                if cve:
                    try:
                        cve_data = cve.get_metadata()
                        metadata["cves"] = [cve_data]
                    except EzeError as error:
                        warnings.append(f"{error}")

                if vulnerable_versions:
                    recommendation = f"Update {pkg_name} ({pkg_version}) to a non vulnerable version, vulnerable versions: {vulnerable_versions}"

                vulnerability_raw = {
                    "vulnerability_type": VulnerabilityType.dependancy.name,
                    "name": pkg_name,
                    "version": pkg_version,
                    "overview": cve_data["summary"] if cve_data else summary,
                    "recommendation": recommendation,
                    "language": self.TOOL_LANGUAGE,
                    "severity": cve_data["severity"] if cve_data else None,
                    "identifiers": {},
                    "metadata": metadata,
                }
                if cve_data:
                    vulnerability_raw["identifiers"]["cve"] = cve_data["id"]
                vulnerability = Vulnerability(vulnerability_raw)
                vulnerabilities_list.append(vulnerability)

        report = ScanResult({"tool": self.TOOL_NAME, "vulnerabilities": vulnerabilities_list, "warnings": warnings})
        return report


def remove_backslash(txt: str):
    """take string and returns it without backslashes"""
    return txt.replace("\\/", "/")
