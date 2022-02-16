"""JSON reporter class implementation"""

from eze.core.reporter import ReporterMeta
from eze.utils.io.file import write_json
from eze.utils.log import log


class JsonReporter(ReporterMeta):
    """Python report class for echoing all output into a json file"""

    REPORTER_NAME: str = "json"
    SHORT_DESCRIPTION: str = "json output file reporter"
    INSTALL_HELP: str = """inbuilt"""
    MORE_INFO: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    VERSION_CHECK: dict = {"FROM_EZE": True}
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": ".eze/eze_report.json",
            "help_text": """report file location
By default set to eze_report.json""",
        }
    }

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output"""
        json_location = write_json(self.config["REPORT_FILE"], scan_results)
        log(f"Written json report : {json_location}")
