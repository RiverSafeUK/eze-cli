"""Eze's Scan Tools module"""
from __future__ import annotations

import asyncio
import os
import time
import math
from abc import ABC, abstractmethod
from typing import Callable

from eze.core.reporter import ReporterManager
from eze.core.config import EzeConfig
from eze.core.enums import VulnerabilitySeverityEnum, ToolType, Vulnerability
from eze.utils.git import get_active_branch_name, get_active_branch_uri
from eze.utils.cli import EzeExecutableNotFoundError
from eze.utils.io import normalise_file_paths, create_folder
from eze.utils.print import pretty_print_table
from eze.utils.config import (
    get_config_key,
    get_config_keys,
    create_config_help,
    extract_embedded_run_type,
)
from eze.utils.error import EzeError, EzeConfigError
from eze.utils.log import log, log_debug, log_error, status_message


class ScanResult:
    """Wrapper around raw dict to provide easy code typing"""

    def __init__(self, vo: dict):
        """constructor"""
        self.tool: str = get_config_key(vo, "tool", str, None)
        self.summary: dict = get_config_key(vo, "summary", dict, {})
        self.run_details: dict = get_config_key(vo, "run_details", dict, {})

        # bom in Cyclonedx format
        # https://cyclonedx.org/
        self.bom: dict = get_config_key(vo, "bom", dict, None)

        raw_vulnerabilities = get_config_key(vo, "vulnerabilities", list, [])
        # rehyrdate vulnerabilities if not Vulnerability Class
        for i, vulnerability in enumerate(raw_vulnerabilities):
            if isinstance(vulnerability, Vulnerability):
                continue
            if isinstance(vulnerability, dict):
                raw_vulnerabilities[i] = Vulnerability(vulnerability)
                continue
            # WARNING: unable to rehydrate poor data
        self.vulnerabilities: list = raw_vulnerabilities

        # String list of Warnings from Tooling
        self.warnings: list = get_config_key(vo, "warnings", list, [])

        # String list of Fatal Errors from Tooling
        # one or more occurrences will
        self.fatal_errors: list = get_config_key(vo, "fatal_errors", list, [])


class ToolMeta(ABC):
    """Base class for all scanner implementations"""

    TOOL_NAME: str = "AbstractTool"
    TOOL_TYPE: ToolType = ToolType.MISC
    SOURCE_SUPPORT: list = []
    SHORT_DESCRIPTION: str = ""
    INSTALL_HELP: str = ""
    MORE_INFO: str = ""
    LICENSE: str = "Unknown"
    EZE_CONFIG: dict = {}
    COMMON_EZE_CONFIG: dict = {
        "ADDITIONAL_ARGUMENTS": {
            "type": str,
            "default": "",
            "help_text": """common field that can be used to postfix arbitrary arguments onto any plugin cli tooling""",
        },
        "IGNORE_BELOW_SEVERITY": {
            "type": str,
            "help_text": """vulnerabilities severities to ignore, by CVE severity level
aka if set to medium, would ignore medium/low/none/na
available levels: critical, high, medium, low, none, na""",
        },
        "IGNORED_VULNERABILITIES": {
            "type": list,
            "help_text": """vulnerabilities to ignore, by CVE code or by name
feature only for use when vulnerability mitigated or on track to be fixed""",
        },
        "IGNORED_FILES": {
            "type": list,
            "help_text": """vulnerabilities in files or prefix folders to ignore
feature only for use when vulnerability mitigated or on track to be fixed""",
        },
        "DEFAULT_SEVERITY": {
            "type": str,
            "help_text": """Severity to set vulnerabilities, when tool doesn't provide a severity, defaults to na
available levels: critical, high, medium, low, none, na""",
        },
        "EXCLUDE": {
            "type": list,
            "default": [],
            "help_text": """files or prefix folders to exclude in the scanning process""",
        },
    }

    def __init__(self, config: dict = None):
        """constructor"""
        if config is None:
            config = {}
        self.config = self._parse_config(config)

    def _parse_config(self, eze_config: dict) -> dict:
        """take raw config dict and normalise values based off "EZE_CONFIG" config,
        can be overridden for advanced behaviours"""
        parsed_config = get_config_keys(eze_config, self.EZE_CONFIG)
        parsed_config = get_config_keys(eze_config, self.COMMON_EZE_CONFIG, parsed_config)
        return parsed_config

    @classmethod
    def tool_type(cls) -> str:
        """Returns tool type"""
        return cls.TOOL_TYPE

    @classmethod
    def source_support(cls) -> str:
        """Returns the sources supported by tool"""
        return cls.SOURCE_SUPPORT

    @classmethod
    def short_description(cls) -> str:
        """Returns short description of tool"""
        return cls.SHORT_DESCRIPTION

    @classmethod
    def more_info(cls) -> str:
        """Returns more info about tool"""
        return cls.MORE_INFO

    @classmethod
    def license(cls) -> str:
        """Returns license of tool"""
        return cls.LICENSE

    @classmethod
    def config_help(cls) -> str:
        """Returns self help instructions how to configure the tool"""
        return create_config_help(cls.TOOL_NAME, cls.EZE_CONFIG, cls.COMMON_EZE_CONFIG)

    @classmethod
    def install_help(cls) -> str:
        """Returns self help instructions how to install the tool"""
        return cls.INSTALL_HELP

    @staticmethod
    @abstractmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""

    @abstractmethod
    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """

    def prepare_folder(self) -> None:
        """Create a reports folder for the plugin report if it does not exist"""
        report_path = self.config.get("REPORT_FILE", None)
        if report_path:
            create_folder(report_path, False)


class ToolManager:
    """Singleton Class for accessing all available Tools"""

    _instance = None

    @staticmethod
    def get_instance() -> ToolManager:
        """Get previously set tools config"""
        if ToolManager._instance is None:
            log_error("ToolManager unable to get config before it is setup")
        return ToolManager._instance

    @staticmethod
    def set_instance(plugins: dict) -> ToolManager:
        """Set the global tools config"""
        ToolManager._instance = ToolManager(plugins)
        return ToolManager._instance

    @staticmethod
    def reset_instance():
        """Reset the global tools config"""
        ToolManager._instance = None

    def __init__(self, plugins: dict = None):
        """takes list of config files, and merges them together, dicts can also be passed instead of pathlib.Path"""
        if plugins is None:
            plugins = {}
        #
        self.tools = {}
        for plugin_name in plugins:
            plugin = plugins[plugin_name]
            if not hasattr(plugin, "get_tools") or not isinstance(plugin.get_tools, Callable):
                log_debug(f"'get_tools' function missing from plugin '{plugin_name}'")
                continue
            plugin_tools = plugin.get_tools()
            self._add_tools(plugin_tools)

    async def run_tool(
        self, tool_name: str, scan_type: str = None, run_type: str = None, parent_language_name: str = None
    ) -> ScanResult:
        """
        Runs a instance of a tool, populated with it's configuration

        :raises EzeConfigError
        """
        tic = time.perf_counter()
        [tool_name, run_type] = extract_embedded_run_type(tool_name, run_type)
        tool_instance = self.get_tool(tool_name, scan_type, run_type, parent_language_name)
        tool_instance.prepare_folder()
        try:
            process = {"scan_result": None}

            async def run_counter(what: str, delay: int = 1):
                status_message(what)
                while True:
                    toc = time.perf_counter()
                    status_message(what + " (" + str(math.ceil(toc - tic)) + " secs)")
                    await asyncio.sleep(delay)

            run_counter_task = asyncio.create_task(run_counter(f"running tool '{tool_name}'"))

            async def run_process():
                try:
                    process["scan_result"] = await tool_instance.run_scan()
                finally:
                    run_counter_task.cancel()

            task_run_process = asyncio.create_task(run_process())
            try:
                await asyncio.gather(run_counter_task, task_run_process)
            except RuntimeError:
                pass
            except asyncio.exceptions.CancelledError:
                pass
            scan_result: ScanResult = process["scan_result"]
        except EzeExecutableNotFoundError as error:
            # Special Case:
            # If executable not installed print "install help"
            # to help user fix error
            tool_class = self.tools[tool_name]
            is_installed = tool_class.check_installed()
            if not is_installed:
                log_error(
                    f"""[{tool_name}] {error}

Looks like {tool_name} is not installed

{tool_name} Install Help:
============================
{tool_class.install_help()}
"""
                )
            scan_result: ScanResult = ScanResult(
                {
                    "tool": tool_instance.TOOL_NAME,
                    "fatal_errors": [f"{error}"],
                }
            )
        except EzeError as error:
            scan_result: ScanResult = ScanResult(
                {
                    "tool": tool_instance.TOOL_NAME,
                    "fatal_errors": [f"{error}"],
                }
            )

        toc = time.perf_counter()
        # annotation raw scan result
        if not scan_result:
            scan_result = ScanResult(
                {
                    "tool": tool_instance.TOOL_NAME,
                    "fatal_errors": ["Not scan result received"],
                }
            )
        if not scan_result.tool:
            scan_result.tool = tool_instance.TOOL_NAME

        git_dir = os.getcwd()
        git_repo = get_active_branch_uri(git_dir)
        git_branch = get_active_branch_name(git_dir)
        scan_result.run_details = {
            "tool_name": tool_name,
            "tool_type": tool_instance.TOOL_TYPE.value,
            "scan_type": scan_type,
            "run_type": run_type,
            "duration_sec": toc - tic,
            "date": tic,
            "git_repo": git_repo,
            "git_branch": git_branch,
        }
        # get tool config for ignore list
        tool_config = self._get_tool_config(tool_name, scan_type, run_type, parent_language_name)
        # normalise vulnerabilities list
        scan_result.vulnerabilities = self._normalise_vulnerabilities(scan_result.vulnerabilities, tool_config)
        # create counts of vulnerabilities
        scan_result.summary = self._create_summary(scan_result.vulnerabilities, tool_config)
        return scan_result

    def get_tool(
        self, tool_name: str, scan_type: str = None, run_type: str = None, parent_language_name: str = None
    ) -> ToolMeta:
        """
        Gets a instance of a tool, populated with it's configuration

        :raises EzeConfigError
        """

        [tool_name, run_type] = extract_embedded_run_type(tool_name, run_type)

        tool_config = self._get_tool_config(tool_name, scan_type, run_type, parent_language_name)
        tool_class = self.tools[tool_name]
        tool_instance = tool_class(tool_config)
        return tool_instance

    def print_tools_list(
        self,
        tool_type: str = None,
        source_type: str = None,
        include_source_type: bool = None,
        include_version: bool = None,
    ):
        """list available tools"""
        log(
            """Available Tools are:
======================="""
        )
        tools = []
        for current_tool_name in self.tools:
            current_tool_class = self.tools[current_tool_name]
            current_tool_type = current_tool_class.tool_type().name
            current_source_support = current_tool_class.source_support()
            current_source_support_strs = list(map(lambda source: source.name, current_source_support))
            current_source_support_str = ",".join(current_source_support_strs)
            current_tool_license = current_tool_class.license()
            current_tool_description = current_tool_class.short_description()
            if tool_type and tool_type != current_tool_type:
                continue
            if (
                source_type
                and source_type not in current_source_support_strs
                and "ALL" not in current_source_support_strs
            ):
                continue
            tool_entry = {}
            tool_entry["Type"] = current_tool_type
            tool_entry["Name"] = current_tool_name
            if include_version:
                current_tool_version = current_tool_class.check_installed() or "Not Installed"
                tool_entry["Version"] = current_tool_version
            tool_entry["License"] = current_tool_license
            if include_source_type:
                tool_entry["Sources"] = current_source_support_str
            tool_entry["Description"] = current_tool_description
            tools.append(tool_entry)

        pretty_print_table(tools)

    def print_tools_help(self, tool_type: str = None, source_type: str = None, include_source_type: bool = None):
        """print help for all tools"""
        log(
            """Available Tools Help:
======================="""
        )
        for current_tool_name in self.tools:
            current_tool_class = self.tools[current_tool_name]
            current_tool_type = current_tool_class.tool_type().name
            current_source_support = current_tool_class.source_support()
            current_source_support_strs = list(map(lambda source: source.name, current_source_support))
            if tool_type and tool_type != current_tool_type:
                continue
            if (
                source_type
                and source_type not in current_source_support_strs
                and "ALL" not in current_source_support_strs
            ):
                continue
            self.print_tool_help(current_tool_name)

    def print_tool_help(self, tool: str):
        """print out tool help"""
        tool_class: ToolMeta = self.tools[tool]
        tool_description = tool_class.short_description()
        log(
            f"""
=================================
Tool '{tool}' Help
{tool_description}
================================="""
        )
        tool_license = tool_class.license()
        log(f"License: {tool_license}")
        tool_version = tool_class.check_installed()
        if tool_version:
            log(f"Version: {tool_version} Installed\n")
        else:
            log(
                """Tool Install Instructions:
---------------------------------"""
            )
            log(tool_class.install_help())
            log("")
        log(
            """Tool Configuration Instructions:
---------------------------------"""
        )
        log(tool_class.config_help())

        log(
            """Tool More Info:
---------------------------------"""
        )
        log(tool_class.more_info())

    def _normalise_vulnerabilities(self, vulnerabilities: list, tool_config: dict) -> list:
        """sort and normalise any corrupted values in vulnerabilities"""
        # normalise any corrupted values
        for vulnerability in vulnerabilities:
            vulnerability.severity = self._get_severity(vulnerability, tool_config)
            vulnerability.update_ignored(tool_config)
            vulnerability.update_excluded(tool_config)
        vulnerabilities = [x for x in vulnerabilities if not x.is_excluded]
        # sort by severity and ignored status
        vulnerabilities = self._sort_vulnerabilities(vulnerabilities)
        return vulnerabilities

    def _create_summary(self, vulnerabilities: list, tool_config: dict) -> list:
        """count vulnerabilities and create summary"""
        summary = {
            "ignored": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "na": 0},
            "totals": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "na": 0},
        }
        for vulnerability in vulnerabilities:
            # increment counters
            if vulnerability.is_ignored:
                summary["ignored"]["total"] += 1
                summary["ignored"][vulnerability.severity] += 1
            else:
                summary["totals"]["total"] += 1
                summary["totals"][vulnerability.severity] += 1
        return summary

    def _sort_vulnerabilities(self, vulnerabilities: list) -> list:
        """sort vulnerabilities by ignored, severity, title"""

        def sort_heuristic(vulnerability: Vulnerability):
            """sort heuristic function"""
            sort_key: str = "b_" if vulnerability.is_ignored else "a_"
            sort_key += str(VulnerabilitySeverityEnum[vulnerability.severity].value) + "_"
            sort_key += str(vulnerability.name) + "_" + str(vulnerability.overview)
            return sort_key

        return sorted(vulnerabilities, key=sort_heuristic)

    def _get_severity(self, vulnerability: Vulnerability, tool_config: dict) -> str:
        """detect severity of vulnerability"""
        severity = (vulnerability.severity or "").lower()
        if hasattr(VulnerabilitySeverityEnum, severity):
            return severity
        return tool_config["DEFAULT_SEVERITY"]

    def _add_tools(self, tools: dict):
        """adds new tools to tools registry"""
        for tool_name in tools:
            tool = tools[tool_name]
            if issubclass(tool, ToolMeta):
                if not hasattr(self.tools, tool_name):
                    log_debug(f"-- installing tool '{tool_name}'")
                    self.tools[tool_name] = tool
                else:
                    log_debug(f"-- skipping '{tool_name}' already defined")
                    continue
            # TODO: else check public functions
            else:
                log_error(f"-- skipping invalid tool '{tool_name}'")
                continue

    def _get_tool_config(
        self, tool_name: str, scan_type: str = None, run_type: str = None, parent_language_name: str = None
    ):
        """
        Get Tool Config, handle default config parameters

        :raises EzeConfigError
        """
        eze_config = EzeConfig.get_instance()
        tool_config = eze_config.get_plugin_config(tool_name, scan_type, run_type, parent_language_name)

        # Warnings for corrupted config
        if tool_name not in self.tools:
            error_message = f"[{tool_name}] The ./ezerc config references unknown tool plugin '{tool_name}', run 'eze tools list' to see available tools"
            raise EzeConfigError(error_message)

        tool_class = self.tools[tool_name]
        default_severity = VulnerabilitySeverityEnum.na.name
        if hasattr(tool_class, "DEFAULT_SEVERITY"):
            default_severity = tool_class.DEFAULT_SEVERITY

        tool_config["DEFAULT_SEVERITY"] = get_config_key(tool_config, "DEFAULT_SEVERITY", str, default_severity)
        if not hasattr(VulnerabilitySeverityEnum, tool_config["DEFAULT_SEVERITY"]):
            log_error(
                f"{tool_name} configured with invalid DEFAULT_SEVERITY='{tool_config['DEFAULT_SEVERITY']}', defaulting to na"
            )
            tool_config["DEFAULT_SEVERITY"] = VulnerabilitySeverityEnum.na.name
        tool_config["IGNORED_VULNERABILITIES"] = get_config_key(tool_config, "IGNORED_VULNERABILITIES", list, [])

        raw_ignored_files = get_config_key(tool_config, "IGNORED_FILES", list, [])
        tool_config["IGNORED_FILES"] = normalise_file_paths(raw_ignored_files)

        raw_excluded_files = get_config_key(tool_config, "EXCLUDE", list, [])
        raw_excluded_files.extend(self.find_tool_output_files(scan_type, run_type, parent_language_name))
        raw_excluded_files.extend(self.find_reporter_files(scan_type, run_type, parent_language_name))
        tool_config["EXCLUDE"] = normalise_file_paths(raw_excluded_files)

        ignore_below_severity_name = get_config_key(
            tool_config, "IGNORE_BELOW_SEVERITY", str, VulnerabilitySeverityEnum.na.name
        )
        if not hasattr(VulnerabilitySeverityEnum, ignore_below_severity_name):
            log_error(f"invalid IGNORE_BELOW_SEVERITY value '{ignore_below_severity_name}' given, defaulting to na")
            ignore_below_severity_name = VulnerabilitySeverityEnum.na.name
        tool_config["IGNORE_BELOW_SEVERITY_INT"] = VulnerabilitySeverityEnum[ignore_below_severity_name].value
        return tool_config

    def find_tool_output_files(self, scan_type: str, run_type: str, parent_language_name: str):
        """Get Tool Config, handle default config parameters"""
        eze_config = EzeConfig.get_instance()
        report_files = []
        for tool_name in self.tools:
            tool_config = eze_config.get_plugin_config(tool_name, scan_type, run_type, parent_language_name)
            report_files.append(tool_config.get("REPORT_FILE", None))
        return [rf for rf in report_files if rf]

    def find_reporter_files(self, scan_type: str, run_type: str, parent_language_name: str):
        """Get Tool Config, handle default config parameters"""
        reporters = []
        try:
            reporters = EzeConfig.get_instance().get_scan_config(scan_type).get("reporters", [])
        except Exception:
            pass
        reporter_manager = ReporterManager.get_instance()
        report_files = []
        for reporter_name in reporters:
            reporter_config = reporter_manager.get_reporter(reporter_name, scan_type, run_type).config
            report_files.append(reporter_config.get("REPORT_FILE", None))
        return [rf for rf in report_files if rf]
