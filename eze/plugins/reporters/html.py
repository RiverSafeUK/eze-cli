"""html reporter class implementation"""

from eze.utils.markdown_print import print_scan_results_as_markdown

from eze import __version__
from eze.core.reporter import ReporterMeta
from eze.utils.io import write_text
from eze.utils.log import log
import markdown


class HtmlReporter(ReporterMeta):
    """Python report class for echoing output into a html report"""

    REPORTER_NAME: str = "html"
    SHORT_DESCRIPTION: str = "html output file formatter"
    INSTALL_HELP: str = """inbuilt"""
    MORE_INFO: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": ".eze/eze_report.html",
            "help_text": """report file location
By default set to eze_report.html""",
        },
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return __version__

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output for html format"""

        report_str = print_scan_results_as_markdown(scan_results=scan_results)
        html_content = markdown.markdown(report_str, output_format="html5", extensions=["tables", "attr_list"])
        html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <title>Eze Scanning report</title>
            </head>

            <body>
                <div class="container">
                    {html_content}
                </div>
            </body>
            </html>
            """
        file_location = write_text(self.config["REPORT_FILE"], html)
        log(f"Written html report : {file_location}")
