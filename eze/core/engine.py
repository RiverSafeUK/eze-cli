"""Core engine of Eze"""
import click
from pydash import py_

from eze.core.config import EzeConfig
from eze.core.language import LanguageManager
from eze.core.reporter import ReporterManager
from eze.core.tool import ToolManager


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

    def auto_build_ezerc(self, build_ezerc: bool = False) -> list:
        """detect if needs to build ezerc from scratch"""
        local_config_location = EzeConfig.get_local_config_filename()
        if not build_ezerc and not local_config_location.is_file():
            click.echo(f"unable to find local config auto generating new config file", err=True)
            build_ezerc = True

        if not build_ezerc:
            return

        click.echo(f"Auto generating a new .ezerc.toml")
        language_manager = LanguageManager.get_instance()
        language_manager.create_local_ezerc_config()
        # reset stored eze config
        EzeConfig.set_eze_config()

    async def run_scan(self, scan_type: str = None) -> list:
        """run a scan with configured tools and reporters"""
        eze_config = EzeConfig.get_instance()
        scan_config = eze_config.get_scan_config(scan_type)

        tools = py_.get(scan_config, "tools", [])
        languages = py_.get(scan_config, "languages", [])
        reporters = scan_config["reporters"]

        return await self.run(tools, languages, reporters, scan_type)

    async def run(self, tools: list, languages: list, reporters: list, scan_type: str = None) -> list:
        """run a scan with set tools and reporters"""
        scan_results = []
        tool_results = await self.run_tools(tools, scan_type)
        scan_results.extend(tool_results)
        language_results = await self.run_languages(languages, scan_type)
        scan_results.extend(language_results)
        return await self.run_reports(scan_results, reporters, scan_type)

    async def run_tools(self, tools: list, scan_type: str = None) -> list:
        """starting scanning for vulnerabilities"""
        results = []
        tool_manager = ToolManager.get_instance()
        for tool_name in tools:
            scan_result = await tool_manager.run_tool(tool_name, scan_type)
            results.append(scan_result)

        return results

    async def run_languages(self, languages: list, scan_type: str = None) -> list:
        """starting scanning for vulnerabilities"""
        results = []
        language_manager = LanguageManager.get_instance()
        for language in languages:
            scan_results = await language_manager.run_language(language, scan_type)
            results.extend(scan_results)

        return results

    async def run_reports(self, scan_results: list, reports: list = None, scan_type: str = None) -> None:
        """starting reporting scan results"""
        if reports is None:
            reports = ["console"]
        #
        reporter_manager = ReporterManager.get_instance()
        for reporter_name in reports:
            await reporter_manager.run_report(scan_results, reporter_name, scan_type)
