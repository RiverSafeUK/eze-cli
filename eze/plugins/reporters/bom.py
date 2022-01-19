"""Bill of Materials reporter class implementation"""

from pydash import py_

from eze import __version__
from eze.core.reporter import ReporterMeta
from eze.utils.io import write_json
from eze.utils.log import log, log_debug, log_error


class BomReporter(ReporterMeta):
    """Python report class for echoing json dx output Bill of Materials"""

    REPORTER_NAME: str = "bom"
    SHORT_DESCRIPTION: str = "json cyclonedx bill of materials reporter"
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
        self._output_sboms(scan_results)

    def _output_sboms(self, scan_results: list):
        """convert scan sboms into bom files"""
        scan_results_with_sboms = []
        for scan_result in scan_results:
            if scan_result.bom:
                scan_results_with_sboms.append(scan_result)

        if len(scan_results_with_sboms) <= 0:
            log_error(
                f"""[{self.REPORTER_NAME}] couldn't find any SBOM data in tool output to convert into SBOM files"""
            )
            return
        for scan_result in scan_results_with_sboms:
            report_file = self.config["REPORT_FILE"]
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            write_json(report_file, scan_result.bom)
            log(f"""Written [{tool_name}] SBOM to {report_file}""")
