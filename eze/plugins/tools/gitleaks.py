"""GitLeaks Python tool class"""
import shlex
import time

from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum, ToolType, SourceType, Vulnerability
from eze.core.tool import (
    ToolMeta,
    ScanResult,
)
from eze.utils.cli.run import run_async_cli_command
from eze.utils.io.file import (
    load_json,
    create_tempfile_path,
)
from eze.utils.log import log


class GitLeaksTool(ToolMeta):
    """GitLeaks Python tool class"""

    TOOL_NAME: str = "gitleaks"
    TOOL_URL: str = "https://github.com/zricethezav/gitleaks"
    TOOL_TYPE: ToolType = ToolType.SECRET
    SOURCE_SUPPORT: list = [SourceType.ALL]
    SHORT_DESCRIPTION: str = "opensource static key scanner"
    INSTALL_HELP: str = """Installation guide for Gitleaks

It is possible to install Gitleaks through:
- Windows:
    1. Download the executable latest release, the appropriate gitleaks-windows-* file.
    2. Rename the file to "gitleaks.exe" and move it to a directory ( i.e. "C:\\Program Files\\Gitleaks").
    3. Finally add the path into ENVIRONMENTAL VARIABLES.

- Linux
    1. Download the appropriate gitleaks-linux-* file.
    2. Rename the downloaded file to "gitleaks" and move it into the executables directory ( /usr/local/bin/gitleaks )

Last step, make sure you are able to run this command:
gitleaks --version
"""
    # https://github.com/zricethezav/gitleaks/blob/master/LICENSE
    LICENSE: str = """MIT"""

    VERSION_CHECK: dict = {"FROM_EXE": "gitleaks --version"}
    MORE_INFO: str = """https://github.com/zricethezav/gitleaks

Helpful tips:
=====================
ADDITIONAL_ARGUMENTS can be used to add additional config for Gitleaks (i.e. rules )
see https://github.com/zricethezav/gitleaks/blob/master/config/default.go"""
    EZE_CONFIG: dict = {
        "SOURCE": {"type": str, "default": ".", "help_text": "Optional folder path to analyse"},
        "CONFIG_FILE": {"type": str, "default": None, "help_text": "Optional file input to customise gitleaks command"},
        "INCLUDE_FULL_REASON": {
            "type": bool,
            "default": True,
            "help_text": """Optional include the full reason in report
Warning: on production might want to set this to False to prevent found Secrets appearing in reports""",
        },
        "VERBOSE": {
            "type": bool,
            "default": True,
            "help_text": """Optional boolean variable to set if the report should be verbose""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-gitleaks-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-gitleaks-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
    }

    DEFAULT_SEVERITY = VulnerabilitySeverityEnum.medium.name
    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": shlex.split("gitleaks --no-git --quiet"),
            # eze config fields -> arguments
            "ARGUMENTS": [],
            # eze config fields -> flags
            "FLAGS": {
                "SOURCE": "--path ",
                "VERBOSE": "-v ",
                "REPORT_FILE": "--report ",
                "CONFIG_FILE": "-c ",
            },
        }
    }

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """

        tic = time.perf_counter()
        completed_process = await run_async_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME)
        toc = time.perf_counter()
        total_time = toc - tic
        if total_time > 10:
            log(
                f"gitleaks scan took a long time ({total_time:0.2f}s), "
                "you can often speed up gitleaks significantly by excluding dependency folders like node_modules, "
                "this can be achieved via adding a gitleaks config file using the CONFIG field in .ezerc.toml"
            )
        parsed_json = load_json(self.config["REPORT_FILE"])
        report = self.parse_report(parsed_json)
        if completed_process.stderr:
            report.warnings.append(completed_process.stderr)

        return report

    def parse_report(self, parsed_json: list) -> ScanResult:
        """convert report json into ScanResult"""
        report_events = parsed_json
        vulnerabilities_list = []
        if report_events:
            for report_event in report_events:
                path = report_event["leakURL"] or report_event["file"]
                reason = report_event["rule"]
                found = report_event["offender"]
                line = report_event["lineNumber"]

                name = f"Found Secret '{reason}'"
                summary = f"Found Secret '{reason}' in {path}"
                recommendation = f"Investigate '{path}' Line {line} for '{reason}' strings"

                # only include full reason if include_full_reason true
                if self.config["INCLUDE_FULL_REASON"]:
                    recommendation += " Full Match: " + found

                vulnerabilities_list.append(
                    Vulnerability(
                        {
                            "vulnerability_type": VulnerabilityType.secret.name,
                            "name": name,
                            "version": None,
                            "overview": summary,
                            "recommendation": recommendation,
                            "language": "file",
                            "severity": self.DEFAULT_SEVERITY,
                            "identifiers": {},
                            "metadata": None,
                            "file_location": {"path": path, "line": line},
                        }
                    )
                )

        report = ScanResult(
            {
                "tool": self.TOOL_NAME,
                "vulnerabilities": vulnerabilities_list,
                "warnings": [],
            }
        )
        return report
