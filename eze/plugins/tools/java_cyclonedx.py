"""cyclonedx SBOM tool class"""
import shlex

from eze.core.enums import ToolType, SourceType
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli import run_cli_command, extract_version_from_maven
from eze.utils.io import create_tempfile_path, create_folder, load_json, write_json


class JavaCyclonedxTool(ToolMeta):
    """cyclonedx java bill of materials generator tool (SBOM) tool class"""

    TOOL_NAME: str = "java-cyclonedx"
    TOOL_TYPE: ToolType = ToolType.SBOM
    SOURCE_SUPPORT: list = [SourceType.JAVA]
    SHORT_DESCRIPTION: str = "opensource java bill of materials (SBOM) generation utility"
    INSTALL_HELP: str = """In most cases all that is required is java and mvn installed

https://maven.apache.org/download.cgi

test with

mvn --version
"""
    MORE_INFO: str = """
https://github.com/CycloneDX/cyclonedx-maven-plugin
https://owasp.org/www-project-cyclonedx/
https://cyclonedx.org/

Tips and Tricks
===========================
You can add org.cyclonedx:cyclonedx-maven-plugin to customise your SBOM output

<plugin>
  <groupId>org.cyclonedx</groupId>
  <artifactId>cyclonedx-maven-plugin</artifactId>
  <version>X.X.X</version>
</plugin>
"""
    # https://github.com/CycloneDX/cyclonedx-maven-plugin/blob/master/LICENSE
    LICENSE: str = """Apache 2.0"""
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-java-cyclonedx-bom.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-java-cyclonedx-bom.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
        "MVN_REPORT_FILE": {
            "type": str,
            "default": "target/bom.json",
            "help_text": "maven output bom.json location, will be loaded, parsed and copied to <REPORT_FILE>",
        },
    }
    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": shlex.split(
                "mvn -Dmaven.test.skip=true clean install org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom"
            )
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        version = extract_version_from_maven("org.cyclonedx:cyclonedx-maven-plugin")
        return version

    async def run_scan(self) -> ScanResult:
        """Method for running a synchronous scan using tool"""
        # AB#608: create report folder
        report_path = self.config["REPORT_FILE"]
        create_folder(report_path)

        completed_process = run_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME)
        cyclonedx_bom = load_json(self.config["MVN_REPORT_FILE"])

        write_json(self.config["REPORT_FILE"], cyclonedx_bom)
        report = self.parse_report(cyclonedx_bom)
        report.warnings = []
        if completed_process.stderr:
            report.warnings.append(completed_process.stderr)

        return report

    def parse_report(self, cyclonedx_bom: dict) -> ScanResult:
        """convert report json into ScanResult"""

        report = ScanResult({"tool": self.TOOL_NAME, "bom": cyclonedx_bom})
        return report
