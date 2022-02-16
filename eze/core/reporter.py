"""Eze's Reports module"""

import time
from abc import abstractmethod
from typing import Callable

from eze.core.config import EzeConfig, PluginMeta
from eze.utils.config import extract_embedded_run_type, create_config_help
from eze.utils.io.print import pretty_print_table
from eze.utils.error import EzeConfigError
from eze.utils.log import log, log_debug, log_error


class ReporterManager:
    """Singleton Class for accessing Report Engine"""

    _instance = None

    @staticmethod
    def get_instance():
        """Get previously set global reporters"""
        if ReporterManager._instance is None:
            log_error("ReporterManager unable to get config before it is setup")
        return ReporterManager._instance

    @staticmethod
    def set_instance(plugins: dict):
        """Set the global reporters"""
        ReporterManager._instance = ReporterManager(plugins)
        return ReporterManager._instance

    @staticmethod
    def reset_instance():
        """Reset the global reporters"""
        ReporterManager._instance = None

    def __init__(self, plugins: dict = None):
        """takes list of config files, and merges them together, dicts can also be passed instead of pathlib.Path"""
        if plugins is None:
            plugins = []
        #
        self.reporters = {}
        for plugin_name in plugins:
            plugin = plugins[plugin_name]
            if not hasattr(plugin, "get_reporters") or not isinstance(plugin.get_reporters, Callable):
                log_debug(f"'get_reporters' function missing from plugin '{plugin_name}'")
                continue
            plugin_reporters = plugin.get_reporters()
            self._add_reporters(plugin_reporters)

    async def run_report(self, scan_results: list, reporter_name: str, scan_type: str = None, run_type: str = None):
        """
        Gets a instance of a reporter, runs report

        :raises EzeConfigError
        """
        tic = time.perf_counter()

        [reporter_name, run_type] = extract_embedded_run_type(reporter_name, run_type)

        reporter_instance = self.get_reporter(reporter_name, scan_type, run_type)
        await reporter_instance.run_report(scan_results)
        toc = time.perf_counter()
        duration_sec = toc - tic
        log_debug(f"\nReport '{reporter_name}' took {duration_sec:0.1f} seconds")

    def get_reporter(self, reporter_name: str, scan_type: str = None, run_type: str = None):
        """
        Gets a instance of a reporter, populated with it's configuration

        :raises EzeConfigError
        """

        [reporter_name, run_type] = extract_embedded_run_type(reporter_name, run_type)

        reporter_config = self.get_reporter_config(reporter_name, scan_type, run_type)
        reporter_class: ReporterMeta = self.reporters[reporter_name]
        reporter_instance = reporter_class(reporter_config)
        return reporter_instance

    def _add_reporters(self, reporters: dict):
        """adds new tools to tools registry"""
        for reporter_name in reporters:
            reporter = reporters[reporter_name]
            if issubclass(reporter, ReporterMeta):
                if not hasattr(self.reporters, reporter_name):
                    log_debug(f"-- installing reporter '{reporter_name}'")
                    self.reporters[reporter_name] = reporter
                else:
                    log_debug(f"-- skipping '{reporter_name}' already defined")
                    continue
            # TODO: else check public functions
            else:
                log_error(f"-- skipping invalid reporter '{reporter_name}'")
                continue

    def get_reporter_config(self, reporter_name: str, scan_type: str = None, run_type: str = None):
        """
        Get Report Config, handle default config parameters

        :raises EzeConfigError
        """
        eze_config = EzeConfig.get_instance()
        # Warnings for corrupted config
        if reporter_name not in self.reporters:
            error_message = f"[{reporter_name}] The ./ezerc config references unknown reporter plugin '{reporter_name}', run 'eze reporters list' to see available reporters"
            raise EzeConfigError(error_message)

        reporter_config = eze_config.get_plugin_config(reporter_name, scan_type, run_type)
        return reporter_config

    def print_reporters_list(self):
        """list available reporters"""
        log(
            """Available Reporters are:
======================="""
        )
        reporters = []
        for reporter_name in self.reporters:
            reporter_class: ReporterMeta = self.reporters[reporter_name]
            reporter_version = reporter_class.check_installed() or "Not Installed"
            reporter_license = reporter_class.license()
            reporter_description = reporter_class.short_description()
            reporters.append(
                {
                    "Name": reporter_name,
                    "Version": reporter_version,
                    "License": reporter_license,
                    "Description": reporter_description,
                }
            )
        pretty_print_table(reporters)

    def print_reporters_help(self):
        """print help for all Reporters"""
        log(
            """Available Reporters Help:
======================="""
        )
        for current_tool_name in self.reporters:
            self.print_reporter_help(current_tool_name)

    def print_reporter_help(self, reporter: str):
        """print out reporter help"""
        reporter_class: ReporterMeta = self.reporters[reporter]
        reporter_description = reporter_class.short_description()
        log(
            f"""=================================
Reporter '{reporter}' Help
{reporter_description}
================================="""
        )
        reporter_version = reporter_class.check_installed()
        if reporter_version:
            log(f"Version: {reporter_version} Installed\n")
        else:
            log(
                """Reporter Install Instructions:
---------------------------------"""
            )
            log(reporter_class.install_help())
            log("")

        log(
            """Reporter Configuration Instructions:
---------------------------------"""
        )
        log(reporter_class.config_help())

        log(
            """Reporter More Info:
---------------------------------"""
        )
        log(reporter_class.more_info())


class ReporterMeta(PluginMeta):
    """Base class for all reporter implementations"""

    REPORTER_NAME: str = "AbstractReporter"

    REPORTER_CONFIG = {}

    @classmethod
    def config_help(cls) -> str:
        """Gives self help instructions how to configure the reporter"""
        return create_config_help(cls.REPORTER_NAME, cls.EZE_CONFIG)

    @abstractmethod
    async def run_report(self, scan_results: list):
        """Method for taking scan results and turning then into report output"""
