"""Safety Python tool class"""
import os
import shlex


from eze.core.enums import VulnerabilityType, ToolType, SourceType, Vulnerability
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli import extract_cmd_version, run_async_cli_command
from eze.utils.cve import detect_cve, get_cve_data
from eze.utils.io import load_json, create_tempfile_path
from eze.utils.error import EzeError


class SafetyTool(ToolMeta):
    """Python SAST Safety tool class"""

    TOOL_NAME: str = "python-safety"
    TOOL_URL: str = "https://pypi.org/project/safety/"
    TOOL_TYPE: ToolType = ToolType.SAST
    SOURCE_SUPPORT: list = [SourceType.PYTHON]
    SHORT_DESCRIPTION: str = "opensource python SCA scanner"
    INSTALL_HELP: str = """In most cases all that is required to install safety is python and pip install
pip install safety
safety --version"""
    MORE_INFO: str = """https://pypi.org/project/safety/

Common Gotchas
===========================
Pip Freezing

A Safety expects exact version numbers. Therefore requirements.txt must be frozen. 

This can be accomplished via:

$ pip freeze > requirements.txt

Tips and Tricks
===============================
to get the latest vulnerabilities in your code (free db only updated monthly),
safety offers a paid real-time vulnerabilty db service look on the safety website for details
"""
    # https://github.com/pyupio/safety/blob/master/LICENSE
    LICENSE: str = """MIT"""
    EZE_CONFIG: dict = {
        #
        "REQUIREMENTS_FILES": {
            "type": list,
            "default": ["requirements.txt"],
            "help_text": """Optional python requirements files to check, defaults to local requirements.txt""",
        },
        "APIKEY": {
            "type": str,
            "default": os.environ.get("SAFETY_APIKEY"),
            "default_help_value": "ENVIRONMENT VARIABLE <SAFETY_APIKEY>",
            "help_text": """By default it uses the open Python vulnerability database Safety DB,
but can be upgraded to use pyup.io's Safety API using the APIKEY option
it can also be specified as the environment variable SAFETY_APIKEY
see https://github.com/pyupio/safety/blob/master/docs/api_key.md""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-safety-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-safety-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
    }

    TOOL_LANGUAGE = "python"
    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": shlex.split("safety check --full-report"),
            # eze config fields -> flags
            "FLAGS": {"APIKEY": "--api=", "REQUIREMENTS_FILES": "-r ", "REPORT_FILE": "--json --output "},
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        version = extract_cmd_version(["safety", "--version"])
        return version

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """
        completed_process = await run_async_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME)

        report_events = load_json(self.config["REPORT_FILE"])
        report = self.parse_report(report_events)
        if completed_process.stderr:
            report.warnings.append(completed_process.stderr)

        return report

    def parse_report(self, parsed_json: list) -> ScanResult:
        """convert report json into ScanResult"""
        report_events = parsed_json
        vulnerabilities = []
        warnings = []

        for report_event in report_events:
            vulnerable_package = report_event[0]
            vulnerable_versions = report_event[1]
            installed_version = report_event[2]
            summary = report_event[3]
            safety_id = report_event[4]
            cve_id = detect_cve(summary)
            cve_data = None
            recommendation = None
            metadata = {"safety": {"id": safety_id}}
            if cve_id:
                try:
                    cve_data = get_cve_data(cve_id)
                except EzeError as error:
                    warnings.append(f"unable to get cve data for {cve_id}, Error: {error}")
            if vulnerable_versions:
                recommendation = f"Update {vulnerable_package} ({installed_version}) to a non vulnerable version, vulnerable versions: {vulnerable_versions}"

            vulnerability_raw = {
                "vulnerability_type": VulnerabilityType.dependency.name,
                "name": vulnerable_package,
                "version": installed_version,
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
            vulnerabilities.append(vulnerability)

        report = ScanResult({"tool": self.TOOL_NAME, "vulnerabilities": vulnerabilities, "warnings": warnings})
        return report
