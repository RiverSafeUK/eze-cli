"""Raw Python tool class"""

from eze import __version__
from eze.core.enums import ToolType, SourceType
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.io import load_json
from eze.utils.error import EzeFileAccessError


class RawTool(ToolMeta):
    """Raw Python tool class for manually in passing previous or generated scan json report"""

    TOOL_NAME: str = "raw"
    TOOL_TYPE: ToolType = ToolType.MISC
    SOURCE_SUPPORT: list = [SourceType.ALL]
    SHORT_DESCRIPTION: str = "input for saved eze json reports"
    INSTALL_HELP: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    MORE_INFO: str = "Tool for ingesting off line and air gapped eze json reports"
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "required": True,
            "help_text": """Eze report file to ingest
normally REPORT_FILE: eze_report.json""",
            "help_example": "eze_report.json",
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        return __version__

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """
        report_file = self.config["REPORT_FILE"]
        try:
            # get first scan in json
            scan_result = load_json(report_file)[0]
            report = ScanResult(scan_result)
            return report
        except EzeFileAccessError:
            raise EzeFileAccessError(f"""Eze Raw tool can not find 'REPORT_FILE' {report_file}""")
