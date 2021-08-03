"""cyclonedx SBOM tool class"""

from eze.core.enums import ToolType, SourceType
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli import extract_cmd_version, run_cli_command
from eze.utils.io import create_tempfile_path, create_folder, load_json


class NodeCyclonedxTool(ToolMeta):
    """cyclonedx node bill of materials generator tool (SBOM) tool class"""

    TOOL_NAME: str = "node-cyclonedx"
    TOOL_TYPE: ToolType = ToolType.SBOM
    SOURCE_SUPPORT: list = [SourceType.NODE]
    SHORT_DESCRIPTION: str = "opensource node bill of materials (SBOM) generation utility"
    INSTALL_HELP: str = """In most cases all that is required is node and npm (version 6+), and cyclonedx installed via npm
        
npm install -g @cyclonedx/bom
"""
    MORE_INFO: str = """
https://github.com/CycloneDX/cyclonedx-node-module
https://owasp.org/www-project-cyclonedx/
https://cyclonedx.org/

Common Gotchas
===========================
NPM Installing

A bill-of-material such as CycloneDX expects exact version numbers. 
Therefore the dependancies in node_modules needs installed

This can be accomplished via:

$ npm install
"""
    # https://github.com/CycloneDX/cyclonedx-node-module/blob/master/LICENSE
    LICENSE: str = """Apache 2.0"""
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-node-cyclonedx-bom.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-node-cyclonedx-bom.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        }
    }

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": ["cyclonedx-bom"],
            # eze config fields -> flags
            "FLAGS": {"REPORT_FILE": "-o "},
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        version = extract_cmd_version(["cyclonedx-bom", "--version"])
        return version

    async def run_scan(self) -> ScanResult:
        """Method for running a synchronous scan using tool"""
        # AB#608: create report folder
        report_path = self.config["REPORT_FILE"]
        create_folder(report_path)

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
