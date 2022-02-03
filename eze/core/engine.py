"""Core engine of Eze"""
import click
from pydash import py_

from eze.core.config import EzeConfig
from eze.core.autoconfig import AutoConfigRunner
from eze.core.reporter import ReporterManager
from eze.core.tool import ToolManager
from eze.utils.log import log, log_debug, log_error


class EzeCore:
    """Singleton Class for accessing Core Eze Engine"""

    _instance = None

    @staticmethod
    def get_instance():
        """Get previously set global core"""
        if EzeCore._instance is None:
            EzeCore._instance = EzeCore()
        return EzeCore._instance

    @staticmethod
    def reset_instance():
        """Reset the global core"""
        EzeCore._instance = None

    def __init__(self):
        """Core Eze Constructor"""

    @staticmethod
    def auto_build_ezerc(force_build_ezerc: bool = False, autoconfig: click.Path = None) -> bool:
        """detect if needs to build ezerc from scratch"""
        valid_config = EzeConfig.has_local_config()
        if not valid_config:
            log_error("unable to find valid local config auto generating new config file")

        build_ezerc = not valid_config or force_build_ezerc
        if not build_ezerc:
            return False

        log("Auto generating a new .ezerc.toml")
        AutoConfigRunner.create_local_ezerc_config(autoconfig)
        # reset stored eze config, to generated version
        EzeConfig.refresh_ezerc_config()
        return True

    async def run_scan(self, scan_type: str = None, custom_reporters: list = None) -> list:
        """run a scan with configured tools and reporters"""
        eze_config = EzeConfig.get_instance()
        scan_config = eze_config.get_scan_config(scan_type)

        tools = py_.get(scan_config, "tools", [])
        reporters = custom_reporters or py_.get(scan_config, "reporters", None)

        return await self.run(tools, reporters, scan_type)

    async def run(self, tools: list, reporters: list, scan_type: str = None) -> list:
        """run a scan with set tools and reporters"""
        scan_results = []
        tool_results = await self.run_tools(tools, scan_type)
        scan_results.extend(tool_results)
        return await self.run_reports(scan_results, reporters, scan_type)

    async def run_tools(self, tools: list, scan_type: str = None) -> list:
        """starting scanning for vulnerabilities"""
        results = []
        tool_manager = ToolManager.get_instance()
        for tool_name in tools:
            scan_result = await tool_manager.run_tool(tool_name, scan_type)
            results.append(scan_result)

        return results

    async def run_reports(self, scan_results: list, reports: list = None, scan_type: str = None) -> None:
        """starting reporting scan results"""
        # default to console report
        if not reports:
            reports = ["console"]
        #
        reporter_manager = ReporterManager.get_instance()
        for reporter_name in reports:
            await reporter_manager.run_report(scan_results, reporter_name, scan_type)
