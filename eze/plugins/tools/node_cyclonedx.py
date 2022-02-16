"""cyclonedx SBOM tool class"""
from pathlib import Path

from eze.core.enums import ToolType, SourceType, LICENSE_CHECK_CONFIG, LICENSE_ALLOWLIST_CONFIG, LICENSE_DENYLIST_CONFIG
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli.run import run_async_cli_command
from eze.utils.io.file import create_tempfile_path, load_json
from eze.utils.language.node import install_npm_in_path
from eze.utils.log import log_debug
from eze.utils.error import EzeExecutableError
from eze.utils.scan_result import convert_multi_sbom_into_scan_result
from eze.utils.io.file_scanner import find_files_by_name


class NodeCyclonedxTool(ToolMeta):
    """cyclonedx node bill of materials generator tool (SBOM) tool class"""

    TOOL_NAME: str = "node-cyclonedx"
    TOOL_URL: str = "https://owasp.org/www-project-cyclonedx/"
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
Therefore the dependencies in node_modules needs installed

This can be accomplished via:

$ npm install

This will be ran automatically, if npm install fails this tool can't be run
"""
    # https://github.com/CycloneDX/cyclonedx-node-module/blob/master/LICENSE
    LICENSE: str = """Apache-2.0"""
    VERSION_CHECK: dict = {"FROM_EXE": "cyclonedx-bom --version"}
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-node-cyclonedx-bom.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-node-cyclonedx-bom.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
        "LICENSE_CHECK": LICENSE_CHECK_CONFIG.copy(),
        "LICENSE_ALLOWLIST": LICENSE_ALLOWLIST_CONFIG.copy(),
        "LICENSE_DENYLIST": LICENSE_DENYLIST_CONFIG.copy(),
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
    def get_process_fatal_errors(completed_process) -> str:
        """Take output and check for common errors"""
        if "node_modules does not exist." in completed_process.stdout:
            return completed_process.stdout
        if "Error: Cannot find module" in completed_process.stdout:
            return completed_process.stdout
        return None

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """
        sboms = {}
        warnings = []
        npm_package_jsons = find_files_by_name("package.json")
        for npm_package in npm_package_jsons:
            log_debug(f"run 'cyclonedx-bom' on {npm_package}")
            npm_project = Path(npm_package).parent
            npm_project_fullpath = Path.joinpath(Path.cwd(), npm_project)
            await install_npm_in_path(npm_project)
            completed_process = await run_async_cli_command(
                self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME, True, cwd=npm_project_fullpath
            )
            fatal_errors = self.get_process_fatal_errors(completed_process)
            if fatal_errors:
                raise EzeExecutableError(fatal_errors)
            sboms[npm_package] = load_json(self.config["REPORT_FILE"])
            if completed_process.stderr:
                warnings.append(completed_process.stderr)

        report = self.parse_report(sboms)
        # add all warnings
        report.warnings.extend(warnings)

        return report

    def parse_report(self, sboms: dict) -> ScanResult:
        """convert report json into ScanResult"""
        return convert_multi_sbom_into_scan_result(self, sboms)
