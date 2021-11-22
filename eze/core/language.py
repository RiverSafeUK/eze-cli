"""Eze's Languages module"""
from __future__ import annotations

import os
import pathlib
import re
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable

import click

from pydash import py_

from eze.core.config import EzeConfig
from eze.core.enums import SourceType
from eze.core.tool import ToolManager
from eze.plugins.tools.semgrep import SemGrepTool
from eze.plugins.tools.trufflehog import TruffleHogTool
from eze.utils.io import write_text
from eze.utils.print import pretty_print_table
from eze.utils.config import extract_embedded_run_type
from eze.utils.error import EzeConfigError


class LanguageRunnerMeta(ABC):
    """Base class for all language implementations
    3 Stages of Eze test
    DISCOVER : RUN

    DISCOVER: USE EXISTING EZERC OR CREATE NEW
    - find
    - create_local_ezerc_config

    RUN:
    - run pre-tool language helper
    - run tools"""

    LANGUAGE_NAME: str = "AbstractLanguage"
    SOURCE_TYPE: SourceType = None
    SHORT_DESCRIPTION: str = ""
    INSTALL_HELP: str = ""
    MORE_INFO: str = ""

    FILE_PATTERNS: dict = {}
    FOLDER_PATTERNS: dict = {}

    def __init__(self, config: dict = None):
        """constructor"""
        self.discovery: LanguageDiscoveryVO = LanguageDiscoveryVO()
        self.discovery.language_name = self.LANGUAGE_NAME
        self.discovery.set_patterns(self.FILE_PATTERNS, self.FOLDER_PATTERNS)

        if config is None:
            config = {}
        self.config = config

    @classmethod
    def language_name(cls) -> str:
        """Returns the language name"""
        return cls.LANGUAGE_NAME

    @classmethod
    def source_type(cls) -> str:
        """Returns the sources supported by tool"""
        return cls.SOURCE_TYPE

    @classmethod
    def short_description(cls) -> str:
        """Returns short description of tool"""
        return cls.SHORT_DESCRIPTION

    @classmethod
    def more_info(cls) -> str:
        """Returns more info about tool"""
        return cls.MORE_INFO

    @classmethod
    def install_help(cls) -> str:
        """Returns self help instructions how to install the tool"""
        return cls.INSTALL_HELP

    @staticmethod
    @abstractmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""

    @abstractmethod
    async def pre_test(self) -> list:
        """Method for running a pre test builds on project"""
        # AB#662: implement auto builds

    @abstractmethod
    def create_ezerc(self) -> dict:
        """Method for building a dynamic ezerc.toml fragment"""


class DefaultRunner(LanguageRunnerMeta):
    """Base class for default language runner"""

    LANGUAGE_NAME: str = "default"
    SOURCE_TYPE: SourceType = SourceType.ALL
    SHORT_DESCRIPTION: str = "default scan profile"
    MORE_INFO: str = """-"""

    FILE_PATTERNS: dict = {}
    FOLDER_PATTERNS: dict = {}

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        return "inbuilt"

    async def pre_test(self) -> list:
        """Method for running a synchronous scan using tool"""
        # AB#662: implement auto builds

    def create_ezerc(self) -> dict:
        """Method for building a dynamic ezerc.toml fragment"""
        fragment = {
            "fragment": f"""
[{self.LANGUAGE_NAME}]
# Eze was unable to find what language the codebase is written in
#
# defaulted to generic SECRET and SAST scanning
# for SCA and SBOM tooling please look at what is available in eze
# and manually configure
#
# eze tools list -t SBOM --include-source-type
# eze tools list -t SCA --include-source-type
#
tools = ['{SemGrepTool.TOOL_NAME}', '{TruffleHogTool.TOOL_NAME}']
    [{self.LANGUAGE_NAME}.{SemGrepTool.TOOL_NAME}]
    REPORT_FILE = "reports/semgrep-report.json"
    CONFIGS = [
        "p/ci"
    ]
    [{self.LANGUAGE_NAME}.{TruffleHogTool.TOOL_NAME}]
    REPORT_FILE = "reports/truffleHog-report.json"
    SOURCE = "."
    IGNORED_FILES = [
        "node_modules/",
        "target/",
        "build/",
        "dist/",
        ".gradle",
        ".aws",
        ".idea",
        ".pytest_cache"
    ]
""",
            "message": """Eze was unable to find what language the codebase is written in

defaulted to generic SECRET and SAST scanning
for SCA and SBOM tooling please look at what is available in eze
and manually configure

eze tools list -t SBOM --include-source-type
eze tools list -t SCA --include-source-type""",
        }
        return fragment


class LanguageDiscoveryVO:
    """Language Discovery object"""

    def __init__(self):
        """constructor"""
        self.is_discovered: bool = False
        self.language_name: str
        self.language_config: dict = {}
        self.folders: dict = {}
        self.files: dict = {}
        self.folder_patterns: dict = {}
        self.file_patterns: dict = {}

    def set_patterns(self, file_patterns: dict, folder_patterns: dict):
        """set patterns to discover"""
        current_regex = None
        try:
            for file_type in file_patterns:
                current_regex = file_patterns[file_type]
                self.file_patterns[file_type] = re.compile(current_regex)
                self.files[file_type] = []

            for folder_type in folder_patterns:
                current_regex = folder_patterns[folder_type]
                self.folder_patterns[folder_type] = re.compile(current_regex)
                self.folders[folder_type] = []
        except:
            raise EzeConfigError(f"Unable to parse regex '{current_regex}'")

    def ingest_discovered_file(self, file_name: str) -> None:
        """Method ingesting file for discovery"""
        for file_type in self.file_patterns:
            is_matching = self.file_patterns[file_type].match(file_name)
            if is_matching:
                self.is_discovered = True
                self.files[file_type].append(file_name)

    def ingest_discovered_folder(self, folder_name: str) -> None:
        """Method ingesting folder for discovery"""
        for folder_type in self.file_patterns:
            is_matching = self.file_patterns[folder_type].match(folder_name)
            if is_matching:
                self.is_discovered = True
                self.folders[folder_type].append(folder_name)


class LanguageManager:
    """Singleton Class for accessing all available Languages"""

    _instance = None

    @staticmethod
    def get_instance() -> LanguageManager:
        """Get previously set languages config"""
        if LanguageManager._instance is None:
            print("Error: LanguageManager unable to get config before it is setup")
        return LanguageManager._instance

    @staticmethod
    def set_instance(plugins: dict) -> LanguageManager:
        """Set the global languages config"""
        LanguageManager._instance = LanguageManager(plugins)
        return LanguageManager._instance

    @staticmethod
    def reset_instance():
        """Reset the global languages config"""
        LanguageManager._instance = None

    def __init__(self, plugins: dict = None):
        """takes list of config files, and merges them together, dicts can also be passed instead of pathlib.Path"""
        if plugins is None:
            plugins = {}
        #
        self.languages = {}
        for plugin_name in plugins:
            plugin = plugins[plugin_name]
            if not hasattr(plugin, "get_languages") or not isinstance(plugin.get_languages, Callable):
                if EzeConfig.debug_mode:
                    print(f"'get_languages' function missing from plugin '{plugin_name}'")
                continue
            plugin_languages = plugin.get_languages()
            self._add_languages(plugin_languages)

    def _discover(self, root_path: str = None) -> list:
        """Discover languages in codebase"""
        ignored_directories = [
            ".git",
            ".idea",
            "node_modules",
            ".gradle",
            "~",
            "__pycache__",
            ".pytest_cache",
            "target",
        ]
        if not root_path:
            root_path = Path.cwd()
        walk_dir = os.path.abspath(root_path)

        root_prefix = len(str(Path(root_path))) + 1

        tmp_languages = {}
        for language_key in self.languages:
            language: LanguageRunnerMeta = self.languages[language_key]()
            tmp_languages[language_key] = language

        for root, subdirs, files in os.walk(walk_dir):
            # Ignore Some directories
            for ignored_directory in ignored_directories:
                if ignored_directory in subdirs:
                    subdirs.remove(ignored_directory)

            for subdir in subdirs:
                folder_path = os.path.join(root, subdir)[root_prefix:]
                for language_key in self.languages:
                    language: LanguageRunnerMeta = tmp_languages[language_key]
                    language.discovery.ingest_discovered_folder(folder_path)

            for filename in files:
                file_path = os.path.join(root, filename)[root_prefix:]
                for language_key in self.languages:
                    language: LanguageRunnerMeta = tmp_languages[language_key]
                    language.discovery.ingest_discovered_file(file_path)

        languages = {}
        for language_key in tmp_languages:
            language: LanguageRunnerMeta = tmp_languages[language_key]
            if language.discovery.is_discovered:
                languages[language_key] = language

        # Default to DefaultRunner
        if py_.values(languages) == 0:
            languages[DefaultRunner.LANGUAGE_NAME] = DefaultRunner()

        return languages

    def _create_config_file(self, config_location: pathlib.Path, config_yaml_str: str) -> None:
        """Create the path to create the config file at and creates file"""
        write_text(config_location, config_yaml_str)
        click.echo(f"Successfully written configuration file to '{config_location}'")

    def create_local_ezerc_config(self, root_path: str = None) -> bool:
        """Create new local ezerc file"""
        languages = self._discover(root_path)
        language_list = []
        eze_rc = """# Ezerc auto generated
# ===================================
# TOOL CONFIG
# ===================================
"""
        for language_key in languages:
            language: LanguageRunnerMeta = languages[language_key]
            output = language.create_ezerc()
            click.echo(f"Found Language '{language_key}':")
            click.echo(output["message"])
            click.echo("\n")
            eze_rc += output["fragment"]
            eze_rc += "\n\n"
            language_list.append('"' + language_key + '"')
        eze_rc += f"""# ===================================
# REPORTER CONFIG
# ===================================
[json]
# Optional JSON_FILE
# By default set to eze_report.json
# REPORT_FILE: XXX-XXX

[bom]
# Optional JSON_FILE
# By default set to eze_report.json
# REPORT_FILE: XXX-XXX

[junit]
# Optional XML_FILE
# By default set to eze_junit_report.xml
# REPORT_FILE: XXX-XXX

[quality]
# Will exit when total number of vulnerabilities in all tools over VULNERABILITY_SEVERITY_THRESHOLD exceeds VULNERABILITY_COUNT_THRESHOLD
# [Optional] defaults to 0
# VULNERABILITY_COUNT_THRESHOLD = 0
# [Optional] defaults to "medium"
# VULNERABILITY_SEVERITY_THRESHOLD = "xxx"
#
# Set Explicit limits for each type of vulnerability
# [Optional] Will when errors of type over limit, not set by default
# VULNERABILITY_CRITICAL_SEVERITY_LIMIT = xxx
# VULNERABILITY_HIGH_SEVERITY_LIMIT = xxx
# VULNERABILITY_MEDIUM_SEVERITY_LIMIT = xxx
# VULNERABILITY_LOW_SEVERITY_LIMIT = xxx
# VULNERABILITY_NONE_SEVERITY_LIMIT = xxx
# VULNERABILITY_NA_SEVERITY_LIMIT = xxx

[console]
PRINT_SUMMARY_ONLY = false
PRINT_IGNORED = false

[scan]
reporters = ["console", "bom", "json", "junit", "quality"]
languages = [{",".join(language_list)}]
"""
        local_config_location = EzeConfig.get_local_config_filename()
        self._create_config_file(local_config_location, eze_rc)
        click.echo(f"Written local configuration file: '{local_config_location}'")

        return True

    def print_languages_list(self):
        """list available languages"""
        click.echo(
            """Available Languages are:
======================="""
        )
        languages = []
        for current_language_name in self.languages:
            current_language_class: LanguageRunnerMeta = self.languages[current_language_name]
            current_language_type = current_language_class.source_type().name
            current_language_version = current_language_class.check_installed() or "Not Installed"
            current_language_description = current_language_class.short_description()

            entry = {
                "Name": current_language_name,
                "Version": current_language_version,
                "Source": current_language_type,
                "Description": current_language_description,
            }
            languages.append(entry)
        pretty_print_table(languages)

    def print_languages_help(self):
        """print help for all Languages"""
        click.echo(
            """Available Languages Help:
======================="""
        )
        for current_tool_name in self.languages:
            self.print_language_help(current_tool_name)

    def print_language_help(self, language: str):
        """print out language help"""
        language_class: LanguageRunnerMeta = self.languages[language]
        language_description = language_class.short_description()
        click.echo(
            f"""=================================
Language '{language}' Help
{language_description}
================================="""
        )
        language_version = language_class.check_installed()
        if language_version:
            click.echo(f"Version: {language_version} Installed\n")
        else:
            click.echo(
                """Language Install Instructions:
---------------------------------"""
            )
            click.echo(language_class.install_help())
            click.echo("")

        click.echo(
            """Language More Info:
---------------------------------"""
        )
        click.echo(language_class.more_info())

    def _add_languages(self, languages: dict):
        """adds new languages to languages registry"""
        for language_name in languages:
            language = languages[language_name]
            if issubclass(language, LanguageRunnerMeta):
                if not hasattr(self.languages, language_name):
                    if EzeConfig.debug_mode:
                        print(f"-- installing language '{language_name}'")
                    self.languages[language_name] = language
                else:
                    if EzeConfig.debug_mode:
                        print(f"-- skipping '{language_name}' already defined")
                    continue
            # TODO: else check public functions
            else:
                if EzeConfig.debug_mode:
                    print(f"-- skipping invalid language '{language_name}'")
                continue

    def get_language_config(self, language_name: str, scan_type: str = None, run_type: str = None):
        """
        Get Language Config, handle default config parameters

        :raises EzeConfigError
        """
        eze_config = EzeConfig.get_instance()
        language_config = eze_config.get_plugin_config(language_name, scan_type, run_type)

        # Warnings for corrupted config
        if language_name not in self.languages:
            error_message = f"[{language_name}] The ./ezerc config references unknown language plugin '{language_name}', run 'eze languages list' to see available languages"
            raise EzeConfigError(error_message)

        # Warnings for corrupted config
        if "tools" not in language_config:
            error_message = f"[{language_name}] The ./ezerc config missing required {language_name}.tools list, run 'eze housekeeping create-local-config' to recreate"
            raise EzeConfigError(error_message)

        return language_config

    def get_language(self, language_name: str, scan_type: str = None, run_type: str = None) -> LanguageRunnerMeta:
        """
        Gets a instance of a language, populated with it's configuration

        :raises EzeConfigError
        """

        [language_name, run_type] = extract_embedded_run_type(language_name, run_type)
        language_config = self.get_language_config(language_name, scan_type, run_type)
        language_class: LanguageRunnerMeta = self.languages[language_name]
        language_instance = language_class(language_config)
        return language_instance

    async def run_language(self, language_name: str, scan_type: str = None, run_type: str = None) -> list:
        """Runs a instance of a tool, populated with it's configuration"""
        [language_name, run_type] = extract_embedded_run_type(language_name, run_type)
        language_instance: LanguageRunnerMeta = self.get_language(language_name, scan_type, run_type)
        # get raw scan result
        tools = language_instance.config["tools"]

        results = []
        tool_manager = ToolManager.get_instance()
        for tool_name in tools:
            scan_result = await tool_manager.run_tool(tool_name, scan_type, None, language_name)
            results.append(scan_result)
        return results
