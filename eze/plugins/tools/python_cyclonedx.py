"""cyclonedx SBOM tool class"""
import shlex

from eze.core.enums import ToolType, SourceType
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli import run_cli_command, detect_pip_executable_version
from eze.utils.io import create_tempfile_path, load_json


class PythonCyclonedxTool(ToolMeta):
    """cyclonedx python bill of materials generator tool (SBOM) tool class"""

    TOOL_NAME: str = "python-cyclonedx"
    TOOL_TYPE: ToolType = ToolType.SBOM
    SOURCE_SUPPORT: list = [SourceType.PYTHON]
    SHORT_DESCRIPTION: str = "opensource python bill of materials (SBOM) generation utility"
    INSTALL_HELP: str = """In most cases all that is required is python and pip (version 3+), and cyclonedx installed via pip

pip install cyclonedx-bom"""
    MORE_INFO: str = """https://github.com/CycloneDX/cyclonedx-python
https://owasp.org/www-project-cyclonedx/
https://cyclonedx.org/

Common Gotchas
===========================
Pip Freezing

A bill-of-material such as CycloneDX expects exact version numbers. Therefore requirements.txt must be frozen. 

This can be accomplished via:

$ pip freeze > requirements.txt
"""
    # https://github.com/CycloneDX/cyclonedx-python/blob/master/LICENSE
    LICENSE: str = """Apache 2.0"""
    EZE_CONFIG: dict = {
        "REQUIREMENTS_FILE": {
            "type": str,
            "default": "",
            "help_text": """defaults to requirements.txt
gotcha: make sure it's a frozen version of the pip requirements""",
            "help_example": "requirements.txt",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-python-cyclonedx-bom.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-python-cyclonedx-bom.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
    }

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": shlex.split("cyclonedx-py -r --format=json --force"),
            # eze config fields -> flags
            "FLAGS": {
                "REQUIREMENTS_FILE": "-i=",
                "REPORT_FILE": "-o=",
            },
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        return detect_pip_executable_version("cyclonedx-bom", "cyclonedx-py")

    async def run_scan(self) -> ScanResult:
        """Method for running a synchronous scan using tool"""

        completed_process = run_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME)

        cyclonedx_bom = load_json(self.config["REPORT_FILE"])
        report = self.parse_report(cyclonedx_bom)
        report.warnings = []
        if completed_process.stderr:
            report.warnings.append(completed_process.stderr)

        return report

    def parse_report(self, cyclonedx_bom: dict) -> ScanResult:
        """convert report json into ScanResult"""

        report = ScanResult({"tool": self.TOOL_NAME, "bom": cyclonedx_bom})
        return report
