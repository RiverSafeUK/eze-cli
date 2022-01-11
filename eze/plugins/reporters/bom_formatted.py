"""Bill of Materials reporter class implementation"""
import shlex

from pydash import py_

from eze.core.reporter import ReporterMeta
from eze.utils.cli import extract_cmd_version, run_cli_command
from eze.utils.io import create_tempfile_path, write_json
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
            "default": "eze_bom.json",
            "help_text": """report file location
By default set to eze_bom.json""",
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
        log("Eze bom results:\n")
        scan_results_with_sboms = []
        for scan_result in scan_results:
            if scan_result.bom:
                scan_results_with_sboms.append(scan_result)

        self._output_sboms(scan_results_with_sboms)

    def _output_sboms(self, scan_results_with_sboms: list):
        """convert scan sboms into bom files"""
        small_indent = "    "
        if len(scan_results_with_sboms) <= 0:
            log(f"""{small_indent}Reporter couldn't find any input sboms to convert into report files""")
            return
        for scan_result in scan_results_with_sboms:
            output_format = self.config["OUTPUT_FORMAT"]
            intermediate_file = self.config["INTERMEDIATE_FILE"]
            report_file = self.config["REPORT_FILE"]
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            log(f"""{small_indent}Writing [{tool_name}] {output_format} SBOM to {report_file}""")
            write_json(intermediate_file, scan_result.bom)
            if output_format == "json":
                # already in json format
                write_json(report_file, scan_result.bom)
            else:
                # convert xml cyclonedx format into json cyclonedx format
                run_cli_command(
                    BomFormattedReporter.REPORTER_CONFIG["CONVERSION_CMD_CONFIG"],
                    self.config,
                    BomFormattedReporter.REPORTER_NAME,
                )
