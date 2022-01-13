"""Bandit Python tool class"""
import json
import shlex

from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum, ToolType, SourceType, Vulnerability
from eze.core.tool import (
    ToolMeta,
    ScanResult,
)
from eze.utils.cli import build_cli_command, extract_cmd_version, run_async_cmd
from eze.utils.io import load_json, create_tempfile_path


class BanditTool(ToolMeta):
    """Bandit Python tool class"""

    TOOL_NAME: str = "python-bandit"
    TOOL_TYPE: ToolType = ToolType.SAST
    SOURCE_SUPPORT: list = [SourceType.PYTHON]
    SHORT_DESCRIPTION: str = "opensource python SAST scanner"
    INSTALL_HELP: str = """In most cases all that is required to install bandit is python and pip install
pip install bandit
bandit --version"""
    MORE_INFO: str = """https://pypi.org/project/bandit/
https://bandit.readthedocs.io/en/latest/

Tips and Tricks
===============================
- exclude tests file as these use non-production functions like assert
  this will avoid lots of False positives
- use IGNORED_FILES to ignore false positives
"""
    # https://github.com/PyCQA/bandit/blob/master/LICENSE
    LICENSE: str = """Apache-2.0"""

    EZE_CONFIG: dict = {
        "SOURCE": {"type": str, "required": True, "help_text": """bandit source folder to scan for python files"""},
        "EXCLUDE": {
            "type": list,
            "default": [],
            "help_text": """array of list of paths (glob patterns supported) to exclude from scan (note that these are in addition to 
the excluded paths provided in the config file)
(default: .svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg)""",
            "help_example": ["PATH-TO-EXCLUDED-FOLDER/.*", "PATH-TO-EXCLUDED-FILE.js"],
        },
        "INI_PATH": {
            "type": str,
            "default": "",
            "help_text": """.bandit config file to use
path to a .bandit file that supplies command line arguments
maps to "--ini INI_PATH""",
            "help_example": "XXX-XXX/.bandit",
        },
        "CONFIG_FILE": {
            "type": str,
            "default": "",
            "help_text": """optional config file to use for selecting plugins and overriding defaults
maps to -c CONFIG_FILE""",
        },
        "INCLUDE_FULL_REASON": {
            "type": bool,
            "default": True,
            "help_text": """Optional include the full reason in report
Warning: on production might want to set this to False to prevent found Secrets appearing in reports""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-bandit-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-bandit-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
    }

    DEFAULT_SEVERITY = VulnerabilitySeverityEnum.high.name

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            "BASE_COMMAND": shlex.split("bandit -f json "),
            # eze config fields -> flags
            "FLAGS": {
                "REPORT_FILE": "-o ",
                #
                "SOURCE": "-r ",
                "CONFIG_FILE": "-c ",
                "INI_PATH": "--ini ",
                "EXCLUDE": "-x ",
            },
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        version = extract_cmd_version(["bandit", "--version"])
        return version

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """
        command_str = build_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config)
        await run_async_cmd(command_str)

        parsed_json = load_json(self.config["REPORT_FILE"])
        report = self.parse_report(parsed_json)
        return report

    def parse_report(self, parsed_json: dict) -> ScanResult:
        """convert report json into ScanResult"""
        report_results = parsed_json["results"]
        vulnerabilities_list = []

        for report_result in report_results:
            path = report_result["filename"]
            reason = report_result["issue_text"]

            line = report_result["line_number"]

            raw_code = report_result["code"]

            name = reason
            summary = f"'{reason}', in {path}"
            recommendation = f"Investigate '{path}' Line {line} for '{reason}' strings"

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
                        "language": "python",
                        "severity": report_result["issue_severity"],
                        "identifiers": {"bandit-code": f"{report_result['test_id']}:{report_result['test_name']}"},
                        "metadata": None,
                        "file_location": {"path": path, "line": line},
                    }
                )
            )

        errors = list(map(json.dumps, parsed_json["errors"]))
        report = ScanResult(
            {
                "tool": self.TOOL_NAME,
                "vulnerabilities": vulnerabilities_list,
                "warnings": errors,
            }
        )
        return report

    def _parse_config(self, eze_config: dict) -> dict:
        """take raw config dict and normalise values"""
        parsed_config = super()._parse_config(eze_config)

        # ADDITION PARSING: EXCLUDE
        # convert to space seperated, clean os specific regex
        if len(parsed_config["EXCLUDE"]) > 0:
            parsed_config["EXCLUDE"] = ",".join(parsed_config["EXCLUDE"])
        else:
            parsed_config["EXCLUDE"] = ""

        return parsed_config
