"""Bill of Materials reporter class implementation"""
import re
import shlex

from pydash import py_

from eze.core.reporter import ReporterMeta
from eze.utils.cli import extract_cmd_version, run_cli_command
from eze.utils.io import create_tempfile_path, write_json, sane
from eze.utils.log import log, log_debug, log_error


class BomFormattedReporter(ReporterMeta):
    """Python report class for echoing all converting Bill of Materials into various formats"""

    REPORTER_NAME: str = "bom-formatted"
    SHORT_DESCRIPTION: str = "bill of materials multiformat reporter"
    INSTALL_HELP: str = """In most cases all that is required to install the cyclonedx-cli binary on path

This is used to convert the raw Cylcone DX JSON into other formats

https://github.com/CycloneDX/cyclonedx-cli/releases"""
    MORE_INFO: str = """https://github.com/CycloneDX/cyclonedx-cli
https://owasp.org/www-project-cyclonedx/
https://cyclonedx.org/

Gotchas
===========================
Executable will need to be renamed after being downloaded
"""
    # https://github.com/CycloneDX/cyclonedx-cli/blob/main/LICENSE
    LICENSE: str = """Apache-2.0"""
    EZE_CONFIG: dict = {
        "OUTPUT_FORMAT": {
            "type": str,
            "default": "json",
            "help_text": """defaults to json, options are csv|json|json_v1_2|spdxtag|spdxtag_v2_1|spdxtag_v2_2|xml|xml_v1_0|xml_v1_1|xml_v1_2
from https://github.com/CycloneDX/cyclonedx-cli Convert Command""",
            "help_example": "json",
        },
        "INTERMEDIATE_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-eze_bom.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-eze_bom.json",
            "help_text": """file used to store json cyclonedx for conversion into final format
By default set to temp file tmp-eze_bom.json""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": "eze_%PROJECT%_bom.json",
            "help_text": """report file location
By default set to eze_%PROJECT%_bom.json %PROJECT% will be substituted for project inventory file aka pom.xml""",
        },
    }

    REPORTER_CONFIG = {
        "CONVERSION_CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": shlex.split("cyclonedx-cli convert"),
            # eze config fields -> flags
            "FLAGS": {
                "REPORT_FILE": "--output-file",
                "INTERMEDIATE_FILE": "--input-file",
                "OUTPUT_FORMAT": "--output-format",
            },
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        version = extract_cmd_version(["cyclonedx-cli", "--version"])
        return version

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output"""
        self._output_sboms(scan_results)

    def _output_sboms(self, scan_results: list):
        """convert scan sboms into bom files"""
        scan_results_with_sboms = []
        for scan_result in scan_results:
            if scan_result.sboms:
                scan_results_with_sboms.append(scan_result)
        if len(scan_results_with_sboms) <= 0:
            log_error(
                f"""[{self.REPORTER_NAME}] couldn't find any SBOM data in tool output to convert into SBOM files"""
            )
            return
        output_format = self.config["OUTPUT_FORMAT"]
        intermediate_file = self.config["INTERMEDIATE_FILE"]
        report_file = self.config["REPORT_FILE"]
        for scan_result in scan_results_with_sboms:
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            for project_name in scan_result.sboms:
                cyclonedx_bom = scan_result.sboms[project_name]
                sane_project_name = sane(project_name)
                project_sbom_report_file = re.sub("%PROJECT%", sane_project_name, report_file)

                write_json(intermediate_file, cyclonedx_bom)
                if output_format == "json":
                    # already in json format
                    write_json(project_sbom_report_file, cyclonedx_bom)
                else:
                    # convert json cyclone-dx format into xxx format
                    self.config["REPORT_FILE"] = project_sbom_report_file
                    run_cli_command(
                        BomFormattedReporter.REPORTER_CONFIG["CONVERSION_CMD_CONFIG"],
                        self.config,
                        BomFormattedReporter.REPORTER_NAME,
                    )
                log(f"""Written [{tool_name}] {output_format} [{project_name}] SBOM to {project_sbom_report_file}""")
