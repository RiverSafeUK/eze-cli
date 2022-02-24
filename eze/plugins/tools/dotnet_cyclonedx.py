"""cyclonedx SBOM tool class"""
import shlex
from pathlib import Path

from eze.core.enums import ToolType, SourceType, LICENSE_CHECK_CONFIG, LICENSE_ALLOWLIST_CONFIG, LICENSE_DENYLIST_CONFIG
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli.run import run_async_cli_command
from eze.utils.log import log_debug
from eze.utils.error import EzeExecutableError
from eze.utils.scan_result import convert_multi_sbom_into_scan_result
from eze.utils.io.file_scanner import find_files_by_name
from eze.utils.io.file import create_tempfile_path, load_json, create_absolute_path


class DotnetCyclonedxTool(ToolMeta):
    """cyclonedx dot net bill of materials generator tool (SBOM) tool class"""

    TOOL_NAME: str = "dotnet-cyclonedx"
    TOOL_URL: str = "https://owasp.org/www-project-cyclonedx/"
    TOOL_TYPE: ToolType = ToolType.SBOM
    SOURCE_SUPPORT: list = [SourceType.DOTNET]
    SHORT_DESCRIPTION: str = "opensource C#/dotnet bill of materials (SBOM) generation utility"
    INSTALL_HELP: str = """In most cases all that is required is dotnet sdk 6+, and to install via nuget

dotnet tool install --global CycloneDX
"""
    MORE_INFO: str = """
https://github.com/CycloneDX/cyclonedx-dotnet
https://owasp.org/www-project-cyclonedx/
https://cyclonedx.org/
"""
    # https://github.com/CycloneDX/cyclonedx-node-module/blob/master/LICENSE

    LICENSE: str = """Apache-2.0"""

    VERSION_CHECK: dict = {"FROM_EXE": "dotnet CycloneDX --version"}

    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-dotnet-cyclonedx-bom"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-dotnet-cyclonedx-bom/bom.json",
            "help_text": "output report directory location (will default to tmp file otherwise)",
        },
        "EXCLUDE_DEV": {
            "type": bool,
            "default": True,
            "help_text": "Exclude development dependencies from the BOM",
        },
        "EXCLUDE_TEST": {
            "type": bool,
            "default": True,
            "help_text": "Exclude test projects from the BOM",
        },
        "LICENSE_CHECK": LICENSE_CHECK_CONFIG.copy(),
        "LICENSE_ALLOWLIST": LICENSE_ALLOWLIST_CONFIG.copy(),
        "LICENSE_DENYLIST": LICENSE_DENYLIST_CONFIG.copy(),
    }

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": shlex.split("dotnet CycloneDX"),
            # eze config fields -> arguments
            "ARGUMENTS": ["INPUT_FILE"],
            # eze config fields -> flags
            "FLAGS": {"REPORT_FILE": "-o "},
            "SHORT_FLAGS": {"EXCLUDE_DEV": "-d", "EXCLUDE_TEST": "-t"},
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
        dotnet_projects = find_files_by_name(".*[.]csproj$")
        dotnet_solutions = find_files_by_name(".*[.]sln$")
        for dotnet_project_file in dotnet_projects + dotnet_solutions:
            log_debug(f"run 'dotnet-cyclonedx' on {dotnet_project_file}")
            project_folder = Path(dotnet_project_file).parent
            scan_config = self.config.copy()
            scan_config["INPUT_FILE"] = Path(dotnet_project_file).name
            scan_config["REPORT_FILE"] = str(create_absolute_path(scan_config["REPORT_FILE"]))
            completed_process = await run_async_cli_command(
                self.TOOL_CLI_CONFIG["CMD_CONFIG"], scan_config, self.TOOL_NAME, True, cwd=project_folder
            )
            fatal_errors = self.get_process_fatal_errors(completed_process)
            if fatal_errors:
                raise EzeExecutableError(fatal_errors)
            sboms[dotnet_project_file] = load_json(Path(self.config["REPORT_FILE"]) / "bom.json")
            if completed_process.stderr:
                warnings.append(completed_process.stderr)
            # "properties": {
            #     "type": "array",
            #     "title": "Properties",
            #     "description": "Provides the ability to document properties in a name-value store. This provides flexibility to include data not officially supported in the standard without having to use additional namespaces or create extensions. Unlike key-value stores, properties support duplicate names, each potentially having different values. Property names of interest to the general public are encouraged to be registered in the [CycloneDX Property Taxonomy](https://github.com/CycloneDX/cyclonedx-property-taxonomy). Formal registration is OPTIONAL.",
            #     "additionalItems": false,
            #     "items": {"$ref": "#/definitions/property"}
            # },
            # annotate transitive packages
            # "properties"."transitive" not "dependency" as too complex to calculate
            # annotate outdated packages
            # "properties"."latest"
            # annotate vulnerabilities packages
            # "vulnerabilities"."vulnerability"
            # https://github.com/CycloneDX/specification/blob/1.4/schema/bom-1.4.schema.json

        report = self.parse_report(sboms)
        # add all warnings
        report.warnings.extend(warnings)

        return report

    def parse_report(self, sboms: dict) -> ScanResult:
        """convert report json into ScanResult"""
        return convert_multi_sbom_into_scan_result(self, sboms)
