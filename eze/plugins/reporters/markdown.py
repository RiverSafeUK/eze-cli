"""Markdown reporter class implementation"""

from eze import __version__
from eze.core.reporter import ReporterMeta
from eze.utils.io import write_text
from eze.utils.log import log

from eze.utils.markdown_print import (
    print_scan_results_as_markdown,
)


class MarkdownReporter(ReporterMeta):
    """Python report class for echoing output into a markdown report"""

    REPORTER_NAME: str = "markdown"
    SHORT_DESCRIPTION: str = "markdown output file formatter"
    INSTALL_HELP: str = """inbuilt"""
    MORE_INFO: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": ".eze/eze_report.md",
            "help_text": """report file location
By default set to eze_report.md""",
        },
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return __version__

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output for markdown format"""

        report_str = print_scan_results_as_markdown(scan_results=scan_results)
        file_location = write_text(self.config["REPORT_FILE"], report_str)
        log(f"Written markdown report : {file_location}")
