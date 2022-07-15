"""TruffleHog v3 Python tool class"""
import json
import re
import shlex
import time
import os

from pydash import py_

from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum, ToolType, SourceType, Vulnerability
from eze.core.tool import (
    ToolMeta,
    ScanResult,
)
from eze.utils.cli.run import run_async_cli_command, run_async_cmd
from eze.utils.io.file import (
    load_json,
    create_tempfile_path,
    remove_non_folders,
    create_absolute_path,
    write_json,
)
from eze.utils.log import log
from eze.utils.io.file_scanner import IGNORED_FOLDERS, cache_workspace_into_tmp
from eze.utils.git import get_gitignore_paths


def extract_leading_number(value: str) -> str:
    """Take output and check for common version patterns"""
    leading_number_regex = re.compile("^[0-9.]+")
    leading_number = re.search(leading_number_regex, value)
    if leading_number:
        return value[leading_number.start() : leading_number.end()]
    return ""


class TruffleHogv3Tool(ToolMeta):
    """TruffleHog v3 Python tool class"""

    MAX_REASON_SIZE: int = 1000

    TOOL_NAME: str = "trufflehog-v3"
    TOOL_URL: str = "https://trufflesecurity.com/"
    TOOL_TYPE: ToolType = ToolType.SECRET
    SOURCE_SUPPORT: list = [SourceType.ALL]
    SHORT_DESCRIPTION: str = "opensource secret scanner"
    INSTALL_HELP: str = """Installation guide for Trufflehog v3
- Download Trufflehog v3 binary:
    1. Download the appropriate trufflehog_*_linux_* executable file.
    2. Rename the downloaded file to "trufflehog" and move it into the executables directory ( /usr/local/bin/trufflehog )
    3. Make sure you are able to run this command:
        trufflehog --version
"""
    MORE_INFO: str = """https://github.com/trufflesecurity/trufflehog/

Tips
===============================
- trufflehog can scan into different sources like: 'git' repos, 'github' organization, 'gitlab', 'filesystem', 's3' buckets.
- use EXCLUDE to not run scan in files
  aka to avoid high entropy ids, or mock passwords in unit test fixtures, (or package-lock.json)
- use IGNORED_FILES to ignore false positives in files and folders
- false positives can be individually omitted with post fixing line with "# nosecret" and "// nosecret"
"""

    LICENSE: str = """GPL"""
    VERSION_CHECK: dict = {"FROM_EXE": "trufflehog --version"}

    EZE_CONFIG: dict = {
        "SOURCE": {
            "type": list,
            "default": ".",
            "required": True,
            "help_text": """TruffleHog v3 list of source folders to scan for secrets""",
        },
        "EXCLUDE": {
            "type": list,
            "default": [],
            "help_text": """array of regex str of folders/files to exclude from scan for secrets
eze will automatically normalise folder separator "/" to os specific versions, "/" for unix, "\\\\" for windows""",
            "help_example": ["PATH-TO-EXCLUDED-FOLDER/.*", "PATH-TO-EXCLUDED-FILE.js", ".*\\.jpeg"],
        },
        "NO_ENTROPY": {
            "type": bool,
            "default": False,
            "help_text": """disable entropy checks, maps to flag --no-entropy""",
        },
        "DISABLE_DEFAULT_IGNORES": {
            "type": bool,
            "default": False,
            "help_text": f"""by default ignores common binary assets folder, ignore list
{ToolMeta.DEFAULT_IGNORED_LOCATIONS}""",
        },
        "CONFIG_FILE": {
            "type": str,
            "help_text": """TruffleHog3 config file to use
see https://github.com/trufflesecurity/trufflehog""",
        },
        "REGEXES_EXCLUDE_FILE": {
            "type": str,
            "help_text": """File with newline separated regexes for files to exclude in the scan.""",
        },
        "INCLUDE_FULL_REASON": {
            "type": bool,
            "default": True,
            "help_text": """Optional include the full reason in report
Warning: on production might want to set this to False to prevent found Secrets appearing in reports""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-truffleHog-v3-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-truffleHog-v3-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
        "USE_GIT_IGNORE": {
            "type": bool,
            "default": True,
            "help_text": """ignore files specified in .gitignore""",
        },
        "USE_SOURCE_COPY": {
            "type": bool,
            "default": True,
            "environment_variable": "USE_SOURCE_COPY",
            "help_text": """speeds up SAST tools by using copied folder with no binary/dependencies assets
for mono-repos can speed up scans from 800s to 30s, by avoiding common dependencies such as node_modules
stored: TMP/.eze/cached-workspace""",
        },
    }
    DEFAULT_SEVERITY = VulnerabilitySeverityEnum.high.name

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix.
            "BASE_COMMAND": shlex.split("trufflehog filesystem --directory . --json"),
            # eze config fields -> flags
            "FLAGS": {"REGEXES_EXCLUDE_FILE": "-r "},
        }
    }

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """

        tic = time.perf_counter()

        scan_config = self.config.copy()
        # make REPORT_FILE absolute in-case cwd changes
        scan_config["REPORT_FILE"] = create_absolute_path(scan_config["REPORT_FILE"])
        cwd = cache_workspace_into_tmp() if self.config["USE_SOURCE_COPY"] else None
        await run_async_cmd(["git", "init"], cwd=cwd)
        completed_process = await run_async_cli_command(
            self.TOOL_CLI_CONFIG["CMD_CONFIG"], scan_config, self.TOOL_NAME, cwd=cwd
        )
        write_json(
            scan_config["REPORT_FILE"], json.loads("[" + ",\n".join(completed_process.stdout.strip().split("\n")) + "]")
        )

        toc = time.perf_counter()
        total_time = toc - tic
        if total_time > 10:
            log(
                f"trufflehog v3 scan took a long time ({total_time:0.2f}s), "
                f"you can often speed up trufflehog significantly by excluding dependency or binary folders like node_modules or sbin"
            )
        parsed_json = load_json(self.config["REPORT_FILE"])
        report = self.parse_report(parsed_json)
        if completed_process.stderr:
            report.warnings.append(completed_process.stderr)

        return report

    def _trufflehog_line(self, report_event):
        """trufflehog format parse support"""
        event_metadata = py_.get(report_event, "SourceMetadata", {})
        path = event_metadata["Data"]["Filesystem"]["file"]
        line = ""
        detector_name = report_event["DetectorName"]
        detector_type = report_event["DetectorType"]
        reason = f"Trufflehog Type: {detector_type} - Sensitive {detector_name}."

        name = f"Found Hardcoded '{reason}' Pattern"
        summary = f"Found Hardcoded '{reason}' Pattern in {path}"
        recommendation = (
            f"Investigate '{path}' Line {line} for '{reason}' strings (add '# nosecret' to line if false positive)"
        )

        # only include full reason if include_full_reason true
        if self.config["INCLUDE_FULL_REASON"]:
            line_containing_secret = report_event["Redacted"]
            if len(line_containing_secret) > self.MAX_REASON_SIZE:
                recommendation += f" Full Match: <on long line ({len(line_containing_secret)} characters)>"
            else:
                recommendation += " Full Match: " + line_containing_secret

        severity = "MEDIUM"

        return Vulnerability(
            {
                "vulnerability_type": VulnerabilityType.secret.name,
                "name": name,
                "version": None,
                "overview": summary,
                "recommendation": recommendation,
                "language": "file",
                "severity": severity,
                "identifiers": {},
                "metadata": None,
                "file_location": {"path": path, "line": line},
            }
        )

    def parse_report(self, parsed_json: list) -> ScanResult:
        """convert report json into ScanResult"""
        report_events = parsed_json
        vulnerabilities_list = []

        for report_event in report_events:
            if report_event != {}:
                vulnerability = self._trufflehog_line(report_event)
                vulnerabilities_list.append(vulnerability)

        report: ScanResult = ScanResult(
            {
                "tool": self.TOOL_NAME,
                "vulnerabilities": vulnerabilities_list,
                "warnings": [],
            }
        )
        return report

    def _parse_config(self, eze_config: dict) -> dict:
        """take raw config dict and normalise values"""
        parsed_config = super()._parse_config(eze_config)

        # remove from SOURCE
        parsed_config["SOURCE"] = remove_non_folders(parsed_config["SOURCE"], ["."], "trufflehog")

        return parsed_config
