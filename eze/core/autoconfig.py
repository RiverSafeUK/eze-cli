"""Eze's Languages module"""
from __future__ import annotations

import json
import os
from pathlib import Path
from pydash import py_

from eze.core.config import EzeConfig
from eze.core.enums import (
    LICENSE_DENYLIST_CONFIG,
    LICENSE_ALLOWLIST_CONFIG,
)
from eze.utils.io.file import write_text, load_json
from eze.utils.log import log, log_debug
from eze.utils.io.file_scanner import find_files_by_name, has_filetype


class AutoConfigRunner:
    """Base class AutoConfig"""

    @staticmethod
    def _is_tool_enabled(tool_config: dict, tool_id: str) -> bool:
        """is tool enabled"""
        if py_.get(tool_config, "enabled_always", False):
            log_debug(f"enabling {tool_id}, always enabled")
            return True
        enable_files = py_.get(tool_config, "enable_on_file", False)
        if enable_files:
            for enable_file in enable_files:
                if len(find_files_by_name(enable_file)) > 0:
                    log_debug(f"enabling {tool_id}, found {enable_file}")
                    return True
        enable_file_exts = py_.get(tool_config, "enable_on_file_ext", False)
        if enable_file_exts:
            for enable_file_ext in enable_file_exts:
                if has_filetype(enable_file_ext) > 0:
                    log_debug(f"enabling {tool_id}, found {enable_file_ext}")
                    return True
        return False

    @staticmethod
    def _create_tool_config_fragment(tool_config: dict, tool_id: str) -> str:
        """create ezerc.toml tool fragment"""
        newline_char = "\n"
        fields_txt = []
        fields = py_.get(tool_config, "config", {})
        for field_id in fields:
            fields_txt.append(f"{field_id} = {json.dumps(fields[field_id], default=vars)}")
        return f"""[{tool_id}]
# Full List of Fields and Tool Help available "docker run riversafe/eze-cli tools help {tool_id}"
{newline_char.join(fields_txt)}
"""

    @staticmethod
    def _create_reporter_config_fragment(reporter_config: dict, reporter_id: str) -> str:
        """create ezerc.toml reporter fragment"""
        newline_char = "\n"
        fields_txt = []
        fields = py_.get(reporter_config, "config", {})
        for field_id in fields:
            fields_txt.append(f"{field_id} = {json.dumps(fields[field_id], default=vars)}")
        return f"""[{reporter_id}]
# Full List of Fields and Reporter Help available "docker run riversafe/eze-cli reporters help {reporter_id}"
{newline_char.join(fields_txt)}
"""

    @staticmethod
    def _create_tools_config(autoconfig_json: dict = None) -> list:
        tool_configs = py_.get(autoconfig_json, "tools", {})
        tool_config_fragments = []
        tool_list = []
        for tool_id in tool_configs:
            tool_config = tool_configs[tool_id]
            is_enabled = AutoConfigRunner._is_tool_enabled(tool_config, tool_id)
            if not is_enabled:
                continue
            tool_list.append(json.dumps(tool_id, default=vars))
            tool_config_fragments.append(AutoConfigRunner._create_tool_config_fragment(tool_config, tool_id))

        return [tool_config_fragments, tool_list]

    @staticmethod
    def _create_reporters_config(autoconfig_json: dict = None) -> list:
        reporter_configs = py_.get(autoconfig_json, "reporters", {})
        reporter_config_fragments = []
        reporter_list = []
        for reporter_id in reporter_configs:
            reporter_config = reporter_configs[reporter_id]
            reporter_list.append(json.dumps(reporter_id, default=vars))
            reporter_config_fragments.append(
                AutoConfigRunner._create_reporter_config_fragment(reporter_config, reporter_id)
            )
        return [reporter_config_fragments, reporter_list]

    @staticmethod
    def create_ezerc_text(autoconfig_json: dict = None) -> str:
        """Method for building a dynamic ezerc.toml fragment"""
        license_mode = py_.get(autoconfig_json, "license.license_mode", "PROPRIETARY")
        [tool_config_fragments, tool_list] = AutoConfigRunner._create_tools_config(autoconfig_json)
        [reporter_config_fragments, reporter_list] = AutoConfigRunner._create_reporters_config(autoconfig_json)

        newline_char = "\n"
        fragment = f"""
# auto generated .ezerc.toml
# recreate with "docker run -t --rm -v DIRECTORY:/data riversafe/eze-cli housekeeping create-local-config"

# ===================================
# GLOBAL CONFIG
# ===================================
[global]
# LICENSE_CHECK, available modes:
# - PROPRIETARY (default) : for commercial projects, check for non-commercial, strong-copyleft, and source-available licenses
# - PERMISSIVE : for permissive open source projects (aka MIT, LGPL), check for strong-copyleft licenses
# - OPENSOURCE : for copyleft open source projects (aka GPL), check for non-OSI or FsfLibre certified licenses
# - OFF : no license checks
# All modes will also warn on "unprofessional", "deprecated", and "permissive with conditions" licenses
LICENSE_CHECK = "{license_mode}"
# LICENSE_ALLOWLIST, {LICENSE_ALLOWLIST_CONFIG["help_text"]}
LICENSE_ALLOWLIST = []
# LICENSE_DENYLIST, {LICENSE_DENYLIST_CONFIG["help_text"]}
LICENSE_DENYLIST = []

# speeds up SAST tools by using copied folder with no binary/dependencies assets
# for mono-repos can speed up scans from 800s to 30s, by avoiding common dependencies such as node_modules
# stored: TMP/.eze/cached-workspace
USE_SOURCE_COPY = true

# Should SCA scan test or development dependencies
INCLUDE_DEV = false

# ========================================
# TOOL CONFIG
# ========================================
# run for available tools "docker run -t --rm riversafe/eze-cli tools list"
{newline_char.join(tool_config_fragments)}

# ========================================
# REPORT CONFIG
# ========================================
# run for available reporters "docker run -t --rm riversafe/eze-cli reporters list"
{newline_char.join(reporter_config_fragments)}

# ========================================
# SCAN CONFIG
# ========================================
[scan]
tools = [{','.join(tool_list)}]
reporters = [{','.join(reporter_list)}]
"""
        return fragment

    @staticmethod
    def get_autoconfig(autoconfig_file: str = None) -> dict:
        """get autoconfig data, defaults to from eze/data/default_autoconfig.json"""
        if not autoconfig_file:
            file_dir = os.path.dirname(__file__)
            autoconfig_file = Path(file_dir) / ".." / "data" / "default_autoconfig.json"
        return load_json(autoconfig_file)

    @classmethod
    def create_local_ezerc_config(cls, autoconfig_file: str = None) -> bool:
        """Create new local ezerc file"""
        autoconfig_data = cls.get_autoconfig(autoconfig_file)
        eze_rc = cls.create_ezerc_text(autoconfig_data)
        local_config_location = EzeConfig.get_local_config_filename()
        write_text(str(local_config_location), eze_rc)
        log(f"Successfully written configuration file to '{local_config_location}'")

        return True


#
# f"""
#
#
# # ===================================
# # TOOL CONFIG
# # ===================================
# """
# for language_key in languages:
#     language: LanguageRunnerMeta = languages[language_key]
#     output = language.create_ezerc()
#     log(f"Found Language '{language_key}':")
#     log(output["message"])
#     log("\n")
#     eze_rc += output["fragment"]
#     eze_rc += "\n\n"
#     language_list.append('"' + language_key + '"')
# eze_rc += f"""# ===================================
# # REPORTER CONFIG
# # ===================================
# [json]
# # Optional JSON_FILE
# # By default set to eze_report.json
# # REPORT_FILE: XXX-XXX
#
# [bom]
# # Optional JSON_FILE
# # By default set to eze_report.json
# # REPORT_FILE: XXX-XXX
#
# [junit]
# # Optional XML_FILE
# # By default set to eze_junit_report.xml
# # REPORT_FILE: XXX-XXX
#
# [quality]
# # Will exit when total number of vulnerabilities in all tools over VULNERABILITY_SEVERITY_THRESHOLD exceeds VULNERABILITY_COUNT_THRESHOLD
# # [Optional] defaults to 0
# # VULNERABILITY_COUNT_THRESHOLD = 0
# # [Optional] defaults to "medium"
# # VULNERABILITY_SEVERITY_THRESHOLD = "xxx"
# #
# # Set Explicit limits for each type of vulnerability
# # [Optional] Will when errors of type over limit, not set by default
# # VULNERABILITY_CRITICAL_SEVERITY_LIMIT = xxx
# # VULNERABILITY_HIGH_SEVERITY_LIMIT = xxx
# # VULNERABILITY_MEDIUM_SEVERITY_LIMIT = xxx
# # VULNERABILITY_LOW_SEVERITY_LIMIT = xxx
# # VULNERABILITY_NONE_SEVERITY_LIMIT = xxx
# # VULNERABILITY_NA_SEVERITY_LIMIT = xxx
#
# [console]
# PRINT_SUMMARY_ONLY = false
# PRINT_IGNORED = false
#
# [scan]
# reporters = ["console", "bom", "json", "junit", "quality"]
# languages = [{",".join(language_list)}]
# """
#
# class LanguageDiscoveryVO:
#     """Language Discovery object"""
#
#     def __init__(self):
#         """constructor"""
#         self.is_discovered: bool = False
#         self.language_name: str
#         self.language_config: dict = {}
#         self.folders: dict = {}
#         self.files: dict = {}
#         self.folder_patterns: dict = {}
#         self.file_patterns: dict = {}
#
#     def set_patterns(self, file_patterns: dict, folder_patterns: dict):
#         """set patterns to discover"""
#         current_regex = None
#         try:
#             for file_type in file_patterns:
#                 current_regex = file_patterns[file_type]
#                 self.file_patterns[file_type] = re.compile(current_regex)
#                 self.files[file_type] = []
#
#             for folder_type in folder_patterns:
#                 current_regex = folder_patterns[folder_type]
#                 self.folder_patterns[folder_type] = re.compile(current_regex)
#                 self.folders[folder_type] = []
#         except:
#             raise EzeConfigError(f"Unable to parse regex '{current_regex}'")
#
#     def ingest_discovered_file(self, file_name: str) -> None:
#         """Method ingesting file for discovery"""
#         for file_type in self.file_patterns:
#             is_matching = self.file_patterns[file_type].match(file_name)
#             if is_matching:
#                 self.is_discovered = True
#                 self.files[file_type].append(file_name)
#
#     def ingest_discovered_folder(self, folder_name: str) -> None:
#         """Method ingesting folder for discovery"""
#         for folder_type in self.file_patterns:
#             is_matching = self.file_patterns[folder_type].match(folder_name)
#             if is_matching:
#                 self.is_discovered = True
#                 self.folders[folder_type].append(folder_name)
#
#
# class LanguageManager:
#     """Singleton Class for accessing all available Languages"""
#
#     _instance = None
#
#     @staticmethod
#     def get_instance() -> LanguageManager:
#         """Get previously set languages config"""
#         if LanguageManager._instance is None:
#             log_error("LanguageManager unable to get config before it is setup")
#         return LanguageManager._instance
#
#     @staticmethod
#     def set_instance(plugins: dict) -> LanguageManager:
#         """Set the global languages config"""
#         LanguageManager._instance = LanguageManager(plugins)
#         return LanguageManager._instance
#
#     @staticmethod
#     def reset_instance():
#         """Reset the global languages config"""
#         LanguageManager._instance = None
#
#     def __init__(self, plugins: dict = None):
#         """takes list of config files, and merges them together, dicts can also be passed instead of pathlib.Path"""
#         if plugins is None:
#             plugins = {}
#         #
#         self.languages = {}
#         for plugin_name in plugins:
#             plugin = plugins[plugin_name]
#             if not hasattr(plugin, "get_languages") or not isinstance(plugin.get_languages, Callable):
#                 log_debug(f"'get_languages' function missing from plugin '{plugin_name}'")
#                 continue
#             plugin_languages = plugin.get_languages()
#             self._add_languages(plugin_languages)
#
#     def _discover(self) -> dict:
#         """Discover languages in codebase"""
#         file_list: str = get_file_list()
#         folder_list: str = get_folder_list()
#
#         tmp_languages = {}
#         for language_key in self.languages:
#             language: LanguageRunnerMeta = self.languages[language_key]()
#             tmp_languages[language_key] = language
#
#         for folder_path in folder_list:
#             for language_key in self.languages:
#                 language: LanguageRunnerMeta = tmp_languages[language_key]
#                 language.discovery.ingest_discovered_folder(folder_path)
#
#         for file_path in file_list:
#             for language_key in self.languages:
#                 language: LanguageRunnerMeta = tmp_languages[language_key]
#                 language.discovery.ingest_discovered_file(file_path)
#
#         languages = {}
#         for language_key in tmp_languages:
#             language: LanguageRunnerMeta = tmp_languages[language_key]
#             if language.discovery.is_discovered:
#                 languages[language_key] = language
#
#         # Default to DefaultRunner
#         if py_.values(languages) == 0:
#             languages[DefaultRunner.LANGUAGE_NAME] = DefaultRunner()
#
#         return languages
#

#
#     def print_languages_list(self):
#         """list available languages"""
#         log(
#             """Available Languages are:
# ======================="""
#         )
#         languages = []
#         for current_language_name in self.languages:
#             current_language_class: LanguageRunnerMeta = self.languages[current_language_name]
#             current_language_type = current_language_class.source_type().name
#             current_language_version = current_language_class.check_installed() or "Not Installed"
#             current_language_description = current_language_class.short_description()
#
#             entry = {
#                 "Name": current_language_name,
#                 "Version": current_language_version,
#                 "Source": current_language_type,
#                 "Description": current_language_description,
#             }
#             languages.append(entry)
#         pretty_print_table(languages)
#
#     def print_languages_help(self):
#         """print help for all Languages"""
#         log(
#             """Available Languages Help:
# ======================="""
#         )
#         for current_tool_name in self.languages:
#             self.print_language_help(current_tool_name)
#
#     def print_language_help(self, language: str):
#         """print out language help"""
#         language_class: LanguageRunnerMeta = self.languages[language]
#         language_description = language_class.short_description()
#         log(
#             f"""=================================
# Language '{language}' Help
# {language_description}
# ================================="""
#         )
#         language_version = language_class.check_installed()
#         if language_version:
#             log(f"Version: {language_version} Installed\n")
#         else:
#             log(
#                 """Language Install Instructions:
# ---------------------------------"""
#             )
#             log(language_class.install_help())
#             log("")
#
#         log(
#             """Language More Info:
# ---------------------------------"""
#         )
#         log(language_class.more_info())
#
#     def _add_languages(self, languages: dict):
#         """adds new languages to languages registry"""
#         for language_name in languages:
#             language = languages[language_name]
#             if issubclass(language, LanguageRunnerMeta):
#                 if not hasattr(self.languages, language_name):
#                     log_debug(f"-- installing language '{language_name}'")
#                     self.languages[language_name] = language
#                 else:
#                     log_debug(f"-- skipping '{language_name}' already defined")
#                     continue
#             # TODO: else check public functions
#             else:
#                 log_debug(f"-- skipping invalid language '{language_name}'")
#                 continue
#
#     def get_language_config(self, language_name: str, scan_type: str = None, run_type: str = None):
#         """
#         Get Language Config, handle default config parameters
#
#         :raises EzeConfigError
#         """
#         eze_config = EzeConfig.get_instance()
#         language_config = eze_config.get_plugin_config(language_name, scan_type, run_type)
#
#         # Warnings for corrupted config
#         if language_name not in self.languages:
#             error_message = f"[{language_name}] The ./ezerc config references unknown language plugin '{language_name}', run 'eze languages list' to see available languages"
#             raise EzeConfigError(error_message)
#
#         # Warnings for corrupted config
#         if "tools" not in language_config:
#             error_message = f"[{language_name}] The ./ezerc config missing required {language_name}.tools list, run 'eze housekeeping create-local-config' to recreate"
#             raise EzeConfigError(error_message)
#
#         return language_config
#
#     def get_language(self, language_name: str, scan_type: str = None, run_type: str = None) -> LanguageRunnerMeta:
#         """
#         Gets a instance of a language, populated with it's configuration
#
#         :raises EzeConfigError
#         """
#
#         [language_name, run_type] = extract_embedded_run_type(language_name, run_type)
#         language_config = self.get_language_config(language_name, scan_type, run_type)
#         language_class: LanguageRunnerMeta = self.languages[language_name]
#         language_instance = language_class(language_config)
#         return language_instance
#
#     async def run_language(self, language_name: str, scan_type: str = None, run_type: str = None) -> list:
#         """Runs a instance of a tool, populated with it's configuration"""
#         [language_name, run_type] = extract_embedded_run_type(language_name, run_type)
#         language_instance: LanguageRunnerMeta = self.get_language(language_name, scan_type, run_type)
#         # get raw scan result
#         tools = language_instance.config["tools"]
#
#         results = []
#         tool_manager = ToolManager.get_instance()
#         for tool_name in tools:
#             scan_result = await tool_manager.run_tool(tool_name, scan_type, None, language_name)
#             results.append(scan_result)
#         return results
