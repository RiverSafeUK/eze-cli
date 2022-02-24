"""cyclonedx SBOM tool class"""
import shlex
from pathlib import Path

from eze.core.enums import ToolType, SourceType, LICENSE_DENYLIST_CONFIG, LICENSE_ALLOWLIST_CONFIG, LICENSE_CHECK_CONFIG
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli.run import run_async_cli_command
from eze.utils.log import log_debug
from eze.utils.io.file import create_tempfile_path, load_json, write_json
from eze.utils.io.file_scanner import find_files_by_name
from eze.utils.scan_result import convert_multi_sbom_into_scan_result
from eze.utils.language.java import ignore_groovy_errors
from eze.utils.data.osv import osv_sca_sboms


class JavaCyclonedxTool(ToolMeta):
    """cyclonedx java bill of materials generator & vulnerability detection tool (SBOM/SCA) tool class"""

    TOOL_NAME: str = "java-cyclonedx"
    TOOL_URL: str = "https://owasp.org/www-project-cyclonedx/"
    TOOL_TYPE: ToolType = ToolType.SBOM
    SOURCE_SUPPORT: list = [SourceType.JAVA]
    SHORT_DESCRIPTION: str = "opensource java bill of materials (SBOM) generation utility, also runs SCA via osv"
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
    LICENSE: str = """Apache-2.0"""
    VERSION_CHECK: dict = {"FROM_MAVEN": "org.cyclonedx:cyclonedx-maven-plugin"}
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
            "help_text": "maven output bom.json location, relative to pom.xml folder, will be loaded, parsed and copied to <REPORT_FILE>",
        },
        # TODO: AB#1047: add option to SCA test dependencies: INCLUDE_TEST -DincludeTestScope=true
        "SCA_ENABLED": {
            "type": bool,
            "default": True,
            "help_text": "use osv data feeds to detect Maven vulnerabilities",
        },
        "LICENSE_CHECK": LICENSE_CHECK_CONFIG.copy(),
        "LICENSE_ALLOWLIST": LICENSE_ALLOWLIST_CONFIG.copy(),
        "LICENSE_DENYLIST": LICENSE_DENYLIST_CONFIG.copy(),
    }
    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": shlex.split(
                "mvn -B -Dmaven.javadoc.skip=true -Dmaven.test.skip=true install org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom"
            )
        }
    }

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """
        warnings_list: list = []
        sboms: dict = {}
        pom_files: list = find_files_by_name("^pom.xml$")

        for pom_file in pom_files:
            log_debug(f"run 'java cyclonedx' on {pom_file}")
            maven_project = Path(pom_file).parent
            maven_project_fullpath = Path.joinpath(Path.cwd(), maven_project)

            completed_process = await run_async_cli_command(
                self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME, cwd=maven_project_fullpath
            )
            bom_fullpath = Path.joinpath(maven_project_fullpath, self.config["MVN_REPORT_FILE"])
            cyclonedx_bom = load_json(str(bom_fullpath))

            write_json(self.config["REPORT_FILE"], cyclonedx_bom)
            sboms[pom_file] = cyclonedx_bom
            if completed_process.stderr:
                tool_warnings = ignore_groovy_errors(completed_process.stderr)
                for tool_warning in tool_warnings:
                    warnings_list.append(tool_warning)

        report = self.parse_report(sboms)
        # add all warnings
        report.warnings.extend(warnings_list)

        return report

    def parse_report(self, cyclonedx_boms: dict) -> ScanResult:
        """convert report json into ScanResult"""
        is_sca_enabled = self.config.get("SCA_ENABLED", False)
        scan_result: ScanResult = convert_multi_sbom_into_scan_result(self, cyclonedx_boms)
        if not is_sca_enabled:
            return scan_result
        # When SCA_ENABLED get SCA vulnerabilities/warnings directly from PYPI
        [osv_vulnerabilities, osv_warnings] = osv_sca_sboms(cyclonedx_boms)
        scan_result.vulnerabilities.extend(osv_vulnerabilities)
        scan_result.warnings.extend(osv_warnings)

        return scan_result
