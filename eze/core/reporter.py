"""Eze's Reports module"""

import time
from abc import ABC, abstractmethod
from typing import Callable

import click

from eze.core.config import EzeConfig, extract_embedded_run_type, ConfigException, get_config_keys, create_config_help
from eze.utils.print import pretty_print_table


class ReporterManager:
    """Singleton Class for accessing Report Engine"""

    _instance = None

    @staticmethod
    def get_instance():
        """Get previously set global reporters"""
        if ReporterManager._instance is None:
            print("Error: ReporterManager unable to get config before it is setup")
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
                if EzeConfig.debug_mode:
                    print(f"'get_reporters' function missing from plugin '{plugin_name}'")
                continue
            plugin_reporters = plugin.get_reporters()
            self._add_reporters(plugin_reporters)

    async def run_report(self, scan_results: list, reporter_name: str, scan_type: str = None, run_type: str = None):
        """Gets a instance of a reporter, runs report"""
        tic = time.perf_counter()

        [reporter_name, run_type] = extract_embedded_run_type(reporter_name, run_type)

        reporter_instance = self.get_reporter(reporter_name, scan_type, run_type)
        await reporter_instance.run_report(scan_results)
        toc = time.perf_counter()
        duration_sec = toc - tic
        print(f"Report '{reporter_name}' took {duration_sec:0.1f} seconds")

    def get_reporter(self, reporter_name: str, scan_type: str = None, run_type: str = None):
        """Gets a instance of a reporter, populated with it's configuration"""

        [reporter_name, run_type] = extract_embedded_run_type(reporter_name, run_type)

        try:
            reporter_config = self.get_reporter_config(reporter_name, scan_type, run_type)
            reporter_class: ReporterMeta = self.reporters[reporter_name]
            reporter_instance = reporter_class(reporter_config)
        except ConfigException as err:
            raise click.ClickException(f"[{reporter_name}] {err.message}")
        return reporter_instance

    def _add_reporters(self, reporters: dict):
        """adds new tools to tools registry"""
        for reporter_name in reporters:
            reporter = reporters[reporter_name]
            if issubclass(reporter, ReporterMeta):
                if not hasattr(self.reporters, reporter_name):
                    if EzeConfig.debug_mode:
                        print(f"-- installing reporter '{reporter_name}'")
                    self.reporters[reporter_name] = reporter
                else:
                    if EzeConfig.debug_mode:
                        print(f"-- skipping '{reporter_name}' already defined")
                    continue
            # TODO: else check public functions
            else:
                if EzeConfig.debug_mode:
                    print(f"-- skipping invalid reporter '{reporter_name}'")
                continue

    def get_reporter_config(self, reporter_name: str, scan_type: str = None, run_type: str = None):
        """Get Report Config, handle default config parameters"""
        eze_config = EzeConfig.get_instance()
        # Warnings for corrupted config
        if reporter_name not in self.reporters:
            error_message = f"The ./ezerc config references unknown reporter plugin '{reporter_name}', run 'eze reporters list' to see available reporters"
            raise click.ClickException(error_message)

        reporter_config = eze_config.get_plugin_config(reporter_name, scan_type, run_type)
        return reporter_config

    def print_reporters_list(self):
        """list available reporters"""
        click.echo(
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
        click.echo(
            """Available Reporters Help:
======================="""
        )
        for current_tool_name in self.reporters:
            self.print_reporter_help(current_tool_name)

    def print_reporter_help(self, reporter: str):
        """print out reporter help"""
        reporter_class: ReporterMeta = self.reporters[reporter]
        reporter_description = reporter_class.short_description()
        click.echo(
            f"""=================================
Reporter '{reporter}' Help
{reporter_description}
================================="""
        )
        reporter_version = reporter_class.check_installed()
        if reporter_version:
            click.echo(f"Version: {reporter_version} Installed")
            click.echo(f"""""")
        else:
            click.echo(
                f"""Reporter Install Instructions:
---------------------------------"""
            )
            click.echo(reporter_class.install_help())
            click.echo(f"""""")

        click.echo(
            f"""Reporter Configuration Instructions:
---------------------------------"""
        )
        click.echo(reporter_class.config_help())

        click.echo(
            f"""Reporter More Info:
---------------------------------"""
        )
        click.echo(reporter_class.more_info())


class ReporterMeta(ABC):
    """Base class for all reporter implementations"""

    REPORTER_NAME: str = "AbstractReporter"
    SHORT_DESCRIPTION: str = ""
    INSTALL_HELP: str = ""
    MORE_INFO: str = ""
    LICENSE: str = "Unknown"
    EZE_CONFIG: dict = {}

    REPORTER_CONFIG = {}

    def __init__(self, config: dict = None):
        """constructor"""
        if config is None:
            config = {}
        self.config = self._parse_config(config)

    def _parse_config(self, config: dict) -> dict:
        """take raw config dict and normalise values, can be overridden for advanced behaviours"""
        parsed_config = get_config_keys(config, self.EZE_CONFIG)
        return parsed_config

    @classmethod
    def short_description(cls) -> str:
        """Gives short description of reporter"""
        return cls.SHORT_DESCRIPTION

    @classmethod
    def more_info(cls) -> str:
        """Gives more info about tool"""
        return cls.MORE_INFO

    @classmethod
    def license(cls) -> str:
        """Returns license of tool"""
        return cls.LICENSE

    @classmethod
    def config_help(cls) -> str:
        """Gives self help instructions how to configure the reporter"""
        return create_config_help(cls.REPORTER_NAME, cls.EZE_CONFIG)

    @classmethod
    def install_help(cls) -> str:
        """Gives self help instructions how to install the reporter"""
        return cls.INSTALL_HELP

    @staticmethod
    @abstractmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""

    @abstractmethod
    async def run_report(self, scan_results: list):
        """Method for taking scan results and turning then into report output"""
