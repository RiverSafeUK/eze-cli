"""Syft SCA and Container SBOM tool class"""

from eze.core.enums import ToolType, SourceType
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli import extract_cmd_version, run_cli_command
from eze.utils.io import create_tempfile_path, create_folder, write_text, load_json


class SyftTool(ToolMeta):
    """Software and Container bill of materials generator tool (SBOM) Syft tool class"""

    TOOL_NAME: str = "anchore-syft"
    TOOL_TYPE: ToolType = ToolType.SBOM
    SOURCE_SUPPORT: list = [
        SourceType.RUBY,
        SourceType.NODE,
        SourceType.JAVA,
        SourceType.PYTHON,
        SourceType.GO,
        SourceType.CONTAINER,
    ]
    SHORT_DESCRIPTION: str = "opensource multi language and container bill of materials (SBOM) generation utility"
    INSTALL_HELP: str = """In most cases all that is two things
        
Syft required to installed via apt-get or docker
As of writing, no native windows 10 syft exists, can be run via wsl2

Also cyclonedx-cli tool for converting xml output into json
https://github.com/CycloneDX/cyclonedx-cli/releases
"""
    MORE_INFO: str = """https://github.com/anchore/syft
https://github.com/CycloneDX/cyclonedx-cli
https://owasp.org/www-project-cyclonedx/
https://cyclonedx.org/

This plugin uses syft to create a xml cyclonedx sbom
Then cyclone-cli to convert that isn't json cyclonedx sbom

Tips
===========================
- if scan running slow, try command locally to see what can be done to optimise the CONFIG_FILE
  (you can see command with --debug)
"""
    # https://github.com/anchore/syft/blob/main/LICENSE
    LICENSE: str = """Apache 2.0"""
    EZE_CONFIG: dict = {
        "SOURCE": {
            "type": str,
            "default": ".",
            "help_example": "python:3.8-slim",
            "help_text": """By default it is "." aka local folder
From syft help
 Supports the following image sources:
    syft packages yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry.
    syft packages path/to/a/file/or/dir      a Docker tar, OCI tar, OCI directory, or generic filesystem directory

  You can also explicitly specify the scheme to use:
    syft packages docker:yourrepo/yourimage:tag          explicitly use the Docker daemon
    syft packages docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
    syft packages oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
    syft packages oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    syft packages dir:path/to/yourproject                read directly from a path on disk (any directory)
    syft packages registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)""",
        },
        "CONFIG_FILE": {
            "type": str,
            "help_text": """Syft config file location, by default Empty, maps to syft argument
-c, --config string     application config file""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-syft-bom.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-syft-bom.json",
            "help_text": "output converted json sbom location (will default to tmp file otherwise)",
        },
        "INTERMEDIATE_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-syft-bom.xml"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-syft-bom.xml",
            "help_text": """file used to store xml cyclonedx from syft before conversion into final json format
(will default to tmp file otherwise)""",
        },
    }
    TOOL_CLI_CONFIG = {
        "CONVERSION_CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": "cyclonedx-cli convert --output-format json",
            # eze config fields -> flags
            "FLAGS": {"REPORT_FILE": "--output-file ", "INTERMEDIATE_FILE": "--input-file "},
        },
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": "syft -o=cyclonedx",
            # eze config fields -> arguments
            "TAIL_ARGUMENTS": ["SOURCE"],
            # eze config fields -> flags
            "FLAGS": {"CONFIG_FILE": "-c="},
        },
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        # requires cyclonedx-cli for xml to json conversion
        extract_cmd_version("cyclonedx-cli --version")
        version = extract_cmd_version("syft version")
        return version

    async def run_scan(self) -> ScanResult:
        """Method for running a synchronous scan using tool"""
        # AB#608: create report folder
        report_path = self.config["REPORT_FILE"]
        create_folder(report_path)

        # create xml cyclonedx using syft
        completed_process = run_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME)
        report_text = completed_process.stdout
        write_text(self.config["INTERMEDIATE_FILE"], report_text)

        # convert xml cyclonedx format into json cyclonedx format
        completed_process = run_cli_command(self.TOOL_CLI_CONFIG["CONVERSION_CMD_CONFIG"], self.config, self.TOOL_NAME)

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
