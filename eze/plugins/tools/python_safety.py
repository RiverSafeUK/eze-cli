"""Safety Python tool class"""
import shlex

from eze.utils.io.file_scanner import find_files_by_name

from eze.core.enums import VulnerabilityType, ToolType, SourceType, Vulnerability
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli.run import run_async_cli_command
from eze.utils.data.cve import detect_cve, get_cve_data
from eze.utils.io.file import load_json, create_tempfile_path
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
    VERSION_CHECK: dict = {"FROM_EXE": "safety --version"}
    EZE_CONFIG: dict = {
        #
        "REQUIREMENTS_FILES": {
            "type": list,
            "default": [],
            "help_text": """surplus custom requirements.txt file
any requirements files named requirements.txt or requirements-dev.txt will be automatically collected
gotcha: make sure it's a frozen version of the pip requirements""",
            "help_example": "[custom-requirements.txt]",
        },
        "APIKEY": {
            "type": str,
            "default": "",
            "environment_variable": "SAFETY_APIKEY",
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
            "FLAGS": {"APIKEY": "--api=", "COMPILED_REQUIREMENTS_FILES": "-r ", "REPORT_FILE": "--json --output "},
        }
    }

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """
        # TODO: migrate from safety, and compare output to integrated pypi feeds from cyclonedx plugin

        requirements_files = find_files_by_name("requirements.txt")
        requirements_files.extend(find_files_by_name("requirements-dev.txt"))
        requirements_files.extend(self.config["REQUIREMENTS_FILES"])
        warnings_list = []

        poetry_files = find_files_by_name("poetry.lock")
        if len(poetry_files):
            warnings_list.append(f"safety does not support poetry files, not scanned: {','.join(poetry_files)}")

        piplock_files = find_files_by_name("Pipfile.lock")
        if len(piplock_files):
            warnings_list.append(f"safety does not support piplock files, not scanned: {','.join(piplock_files)}")

        if not len(requirements_files):
            warnings_list.append("safety not ran, no python requirements files found")
            return ScanResult(
                {
                    "tool": self.TOOL_NAME,
                    "warnings": warnings_list,
                }
            )

        scan_config = {"COMPILED_REQUIREMENTS_FILES": requirements_files}
        scan_config = {**scan_config, **self.config.copy()}
        completed_process = await run_async_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], scan_config, self.TOOL_NAME)

        report_events = load_json(self.config["REPORT_FILE"])
        report = self.parse_report(report_events)
        if completed_process.stderr:
            warnings_list.append(completed_process.stderr)

        # add all warnings
        report.warnings.extend(warnings_list)

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
