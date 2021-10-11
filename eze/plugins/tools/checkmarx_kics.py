"""Checkmarx Kics Container tool class"""
import shlex
import os

from pydash import py_

from eze.core.enums import VulnerabilityType, ToolType, SourceType
from eze.core.tool import (
    ToolMeta,
    Vulnerability,
    ScanResult,
)
from eze.utils.cli import extract_cmd_version, run_cli_command
from eze.utils.io import load_json, create_tempfile_path


class KicsTool(ToolMeta):
    """SCA Container Kics tool class"""

    TOOL_NAME: str = "container-kics"
    TOOL_TYPE: ToolType = ToolType.SCA
    SOURCE_SUPPORT: list = [SourceType.CONTAINER]
    SHORT_DESCRIPTION: str = "opensource infrastructure scanner"
    INSTALL_HELP: str = """Installation guide for KICS

It is possible to install Gitleaks through:
- Running install command:
    1. There is an automatic detection to download the appropriate latest binary package, just run: 
    `curl -sfL 'https://raw.githubusercontent.com/Checkmarx/kics/master/install.sh' | bash`.
    2. Move the file kics.exe to a specific directory ( i.e. "C:\\Program Files\\Kics").

- Downloading KICS binary:
    1. Download the appropriate kics_*_linux_* executable file.
    2. Rename the downloaded file to "kics" and move it into the executables directory ( /usr/local/bin/kics )

Last step, make sure you are able to run this command:
    kics --version
"""
    MORE_INFO: str = """https://github.com/Checkmarx/kics

Common Gotchas
===========================
You can use the Docker image available on https://hub.docker.com/r/checkmarx/kics
or by using the command `docker pull checkmarx/kics:latest`


Also you can define a custom config file and pass the --config flag.
"""
    # https://github.com/Checkmarx/kics/blob/master/LICENSE
    LICENSE: str = """Apache 2.0"""
    EZE_CONFIG: dict = {
        "SOURCE": {
            "type": str,
            "required": True,
            "help_text": """source folder to scan for IAC files, paths comma-separated""",
        },
        "CONFIG_FILE": {"type": str, "default": None, "help_text": "Optional file input to customise scan command"},
        "EXCLUDE": {
            "type": list,
            "default": [],
            "help_text": """array of regex str of folders/files to exclude from scan,
eze will automatically normalise folder separator "/" to os specific versions, "/" for unix, "\\\\" for windows""",
            "help_example": ["PATH-TO-EXCLUDED-FOLDER/.*", "PATH-TO-EXCLUDED-FILE.js", ".*\\.jpeg"],
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-kics-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-kics-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
        "INCLUDE_FULL_REASON": {
            "type": bool,
            "default": True,
            "help_text": """Optional include the full reason in report
Warning: on production might want to set this to False to prevent found Secrets appearing in reports""",
        },
    }

    TOOL_LANGUAGE = "container"
    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": shlex.split("kics scan -s -p"),
            # eze config fields -> arguments
            "ARGUMENTS": ["SOURCE"],
            # eze config fields -> flags
            "FLAGS": {
                "REPORT_PATH": "--output-path ",
                "REPORT_FILENAME": "--output-name ",
                "CONFIG_FILE": "--config ",
            },
            "FLAGS_WITH_MULTI_FIELDS": {
                "EXCLUDE": "-e=",
            },
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting tool installed and ready to run scan, returns version installed"""
        version = extract_cmd_version(["kics", "version"])
        print(version)
        return version

    async def run_scan(self) -> ScanResult:
        """Method for running a synchronous scan using tool"""

        completed_process = run_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME)
        report_events = load_json(self.config["REPORT_FILE"])
        report = self.parse_report(report_events)
        report.warnings = []
        if completed_process.stderr:
            report.warnings.append(completed_process.stderr)

        return report

    def parse_report(self, parsed_json: list) -> ScanResult:
        """convert report json into ScanResult"""
        report_events = py_.get(parsed_json, "queries", [])

        vulnerabilities_list = []
        if report_events:
            for report_event in report_events:
                if report_event["files"]:
                    files = report_event["files"]
                    for file in files:
                        reason = report_event["query_name"]
                        path = file["file_name"]
                        line = file["line"]
                        identifier = file["issue_type"]

                        name = reason
                        summary = f"{file['actual_value']} - {identifier} on {report_event['platform']}"
                        recommendation = (
                            f"Investigate '{path}' on line {line} for '{reason}'. Expected '{file['expected_value']}'. "
                        )

                        # only include full reason if include_full_reason true
                        if self.config["INCLUDE_FULL_REASON"]:
                            recommendation += f"Full Match: {file['search_key']} - {file['actual_value']}."

                        vulnerabilities_list.append(
                            Vulnerability(
                                {
                                    "vulnerability_type": VulnerabilityType.infrastructure.name,
                                    "name": name,
                                    "overview": summary,
                                    "recommendation": recommendation,
                                    "language": self.TOOL_LANGUAGE,
                                    "severity": report_event["severity"],
                                    "identifiers": identifier,
                                    "references": report_event["query_url"],
                                    "file_location": {"path": path, "line": line},
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

    def _parse_config(self, eze_config: dict) -> dict:
        """take raw config dict and normalise values"""
        parsed_config = super()._parse_config(eze_config)
        old_report_flag = parsed_config["REPORT_FILE"]
        # ADDITION PARSING: OUTPUT_PATH FLAGS
        # convert to separated arguments to fit the plugin
        parsed_config["REPORT_PATH"] = os.path.dirname(old_report_flag)
        parsed_config["REPORT_FILENAME"] = os.path.basename(old_report_flag)

        return parsed_config
