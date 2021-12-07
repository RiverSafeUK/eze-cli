"""Bill of Materials reporter class implementation"""
import click
from pydash import py_

from eze import __version__
from eze.core.reporter import ReporterMeta
from eze.utils.io import write_json
from eze.utils.log import log, log_debug, log_error


class BomReporter(ReporterMeta):
    """Python report class for echoing json dx output Bill of Materials"""

    REPORTER_NAME: str = "bom"
    SHORT_DESCRIPTION: str = "json dx bill of materials reporter"
    INSTALL_HELP: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": "eze_bom.json",
            "help_text": """report file location
By default set to eze_bom.json""",
        },
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return __version__

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
            report_file = self.config["REPORT_FILE"]
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            log(f"""{small_indent}Writing [{tool_name}] json dx SBOM to {report_file}""")
            write_json(report_file, scan_result.bom)
