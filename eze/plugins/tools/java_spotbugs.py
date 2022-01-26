"""Spotbugs java tool class to detect bugs inside the project"""
import re
import shlex

import xmltodict

from eze.core.enums import VulnerabilityType, ToolType, SourceType, Vulnerability
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli import extract_version_from_maven, run_async_cli_command
from eze.utils.io import create_tempfile_path, write_json
from eze.utils.language.java import ignore_groovy_errors


class JavaSpotbugsTool(ToolMeta):
    """Spotbugs SAST tool class"""

    TOOL_NAME: str = "java-spotbugs"
    TOOL_URL: str = "https://spotbugs.github.io/"
    TOOL_TYPE: ToolType = ToolType.SAST
    SOURCE_SUPPORT: list = [SourceType.JAVA]
    SHORT_DESCRIPTION: str = "opensource java SAST tool class"
    INSTALL_HELP: str = """In most cases all that is required is java and mvn installed

https://maven.apache.org/download.cgi

test if installed with

mvn --version
"""
    MORE_INFO: str = """
https://spotbugs.github.io/
https://github.com/spotbugs/spotbugs
https://spotbugs.readthedocs.io/en/latest/maven.html

Tips and Tricks
===========================
You can add files to include or exclude to customise your output
https://spotbugs.readthedocs.io/en/latest/filter.html
"""
    # https://github.com/spotbugs/spotbugs/blob/master/LICENSE
    LICENSE: str = """LGPL"""
    EZE_CONFIG: dict = {
        "INCLUDE_FULL_REASON": {
            "type": bool,
            "default": True,
            "help_text": """Optional include the full reason in report
Warning: on production might want to set this to False to prevent found Secrets appearing in reports""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-java-spotbugs.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-java-spotbugs.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
        "MVN_REPORT_FILE": {
            "type": str,
            "default": "target/spotbugsXml.xml",
            "help_text": "maven output spotbugsXml.xml location, will be loaded, parsed and copied to <REPORT_FILE>",
        },
    }

    TOOL_LANGUAGE = "java"
    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            # https://spotbugs.github.io/spotbugs-maven-plugin/check-mojo.html
            "BASE_COMMAND": shlex.split(
                "mvn -B -Dmaven.javadoc.skip=true -Dmaven.test.skip=true install com.github.spotbugs:spotbugs-maven-plugin:check"
            )
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        version = extract_version_from_maven("com.github.spotbugs:spotbugs-maven-plugin")
        return version

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """

        completed_process = await run_async_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME)
        with open(self.config["MVN_REPORT_FILE"]) as xml_file:
            spotbugs_report = xmltodict.parse(xml_file.read(), force_list={"BugInstance", "BugPattern"})

        write_json(self.config["REPORT_FILE"], spotbugs_report)
        report = self.parse_report(spotbugs_report)

        if completed_process.stderr:
            warnings = ignore_groovy_errors(completed_process.stderr)
            for warning in warnings:
                report.warnings.append(warning)

        return report

    def parse_report(self, parsed_json: dict) -> ScanResult:
        """convert report json into ScanResult"""
        report_results = parsed_json["BugCollection"]
        vulnerabilities_list = []

        if "BugInstance" in report_results:
            bug_patterns = {}
            for bug_pattern in report_results["BugPattern"]:
                if bug_pattern["@type"] in bug_patterns:
                    continue
                bug_patterns[bug_pattern["@type"]] = bug_pattern["Details"]

            for bug_instance in report_results["BugInstance"]:
                bug_sourceline = bug_instance["Class"]["SourceLine"]

                path = bug_sourceline["@sourcepath"]
                reason = bug_instance["ShortMessage"]
                line = bug_sourceline["@start"] + "-" + bug_sourceline["@end"]
                raw_code = bug_instance["LongMessage"]
                name = reason
                summary = f"'{reason}', in {path}"
                details = re.sub("<[^>]*>", "", bug_patterns[bug_instance["@type"]])

                recommendation = f"Investigate '{path}' Lines {line} for '{reason}' \n  {details}"

                bug_category = bug_instance["@category"]
                priority = {"1": "high", "2": "medium", "3": "low"}[bug_instance["@priority"]]

                # only include full reason if include_full_reason true
                if self.config["INCLUDE_FULL_REASON"]:
                    recommendation += " Full Match: " + raw_code
                vulnerabilities_list.append(
                    Vulnerability(
                        {
                            "vulnerability_type": VulnerabilityType.code.name,
                            "name": name,
                            "version": None,
                            "overview": summary,
                            "recommendation": recommendation,
                            "language": "java",
                            "severity": priority,
                            "identifiers": {
                                "spotbugs-code": f"{bug_instance['@type']}:{bug_instance['ShortMessage']} ({bug_category})"
                            },
                            "metadata": None,
                            "file_location": {"path": path, "lines": bug_sourceline["@start"]},
                        }
                    )
                )

        report = ScanResult(
            {
                "tool": self.TOOL_NAME,
                "vulnerabilities": vulnerabilities_list,
            }
        )
        return report
