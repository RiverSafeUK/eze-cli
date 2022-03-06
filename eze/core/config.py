"""
Singleton Class for storing Global Eze Config

This takes multiple TOML files

See table for reason why toml not json/yaml was chosen,
also it's what all the cool rust and python projects use
https://www.python.org/dev/peps/pep-0518/#overview-of-file-formats-considered
"""
from eze import __version__
from pathlib import Path
import click
from pydash import py_
import shlex
from abc import ABC
from copy import deepcopy

from eze.utils.io.file import load_toml
from eze.utils.config import (
    extract_embedded_run_type,
    merge_from_root_base,
    merge_from_root_flat,
    merge_from_root_nested,
    merge_configs,
    get_config_keys,
)
from eze.utils.error import EzeFileAccessError, EzeFileParsingError, EzeConfigError
import semantic_version
from eze.utils.error import EzeError
from eze.utils.log import log, log_debug, log_error
from eze.utils.cli.version import extract_cmd_version, extract_version_from_maven, detect_pip_executable_version


class EzeConfig:
    """Singleton Class for accessing and merging multiple config files"""

    _instance = None

    @staticmethod
    def get_global_config_filename() -> Path:
        """Path of global configuration file"""
        raw_path = click.get_app_dir("eze", roaming=False, force_posix=False)
        global_config_file = Path(raw_path) / "config.toml"
        return global_config_file

    @staticmethod
    def get_local_config_filename() -> Path:
        """Path of local configuration file"""
        local_config_file = Path.cwd() / ".ezerc.toml"
        return local_config_file

    @staticmethod
    def has_local_config() -> bool:
        """Is local .ezerc present"""
        try:
            local_config = EzeConfig.get_local_config_filename()
            if not local_config.is_file():
                return False
            load_toml(local_config)
            return True
        except EzeFileParsingError:
            return True
        except EzeFileAccessError:
            return False

    @staticmethod
    def refresh_ezerc_config(external_file: str = None):
        """refresh and rebuild cached eze config

        Precedence:

        - External Config File via command line (-c/-config="xxx.yaml")
        - Config in local .ezerc.toml file
        - Config in app-data folder .eze/config.toml

        First In First Last ordering of keys

        aka keys set in app-data will be overwritten in local or cli send config

        .. Notes:: https://click.palletsprojects.com/en/7.x/api/#click.get_app_dir
        """

        global_config_file = EzeConfig.get_global_config_filename()
        local_config_file = EzeConfig.get_local_config_filename()

        log_debug(
            f"""Setting Eze's Config:
    =========================
    Locations Searching
        global_config_file: {global_config_file}
        local_config_file: {local_config_file}
        external_file: {external_file}
    """
        )
        return EzeConfig.set_instance([global_config_file, local_config_file, external_file])

    @staticmethod
    def get_instance():
        """Get previously set config"""
        if EzeConfig._instance is None:
            log_error("EzeConfig unable to get config before it is setup")
        return EzeConfig._instance

    @staticmethod
    def set_instance(config_files):
        """Set the global config"""
        EzeConfig._instance = EzeConfig(config_files)
        return EzeConfig._instance

    @staticmethod
    def reset_instance():
        """Set the global config"""
        EzeConfig._instance = None

    def __init__(self, config_files: list = None):
        """takes list of config files, and merges them together, dicts can also be passed instead of pathlib.Path"""
        if config_files is None:
            config_files = []
        #
        self.config = {}
        for config_file in config_files:
            try:
                if config_file is None:
                    continue
                if isinstance(config_file, dict):
                    merge_configs(config_file, self.config)
                    continue
                parsed_config = load_toml(config_file)
                merge_configs(parsed_config, self.config)
            except EzeFileAccessError:
                log_debug(f"-- [CONFIG ENGINE] skipping file as not found '{config_file}'")
                continue
            except EzeFileParsingError as error:
                log_error(f"-- [CONFIG ENGINE] skipping file as toml is corrupted, {error}")
                continue

    def get_scan_config(self, scan_type: str = None) -> dict:
        """Gives scan's configuration, defaults to standard scan, but can be named scan"""
        scan_config = {}
        # clone default plugin config
        if "scan" in self.config:
            merge_configs(self.config["scan"], scan_config)
        # append custom named scan config
        if "scan" in self.config and scan_type in self.config["scan"]:
            named_scan_config = self.config["scan"][scan_type]
            merge_configs(named_scan_config, scan_config)

        # Warnings for corrupted config
        if "tools" not in scan_config:
            error_message = "The ./ezerc config missing required scan.tools list, run 'docker run -t --rm -v DIRECTORY:/data riversafe/eze-cli housekeeping create-local-config' to create"
            raise EzeConfigError(error_message)

        if "reporters" not in scan_config:
            error_message = "The ./ezerc config missing scan.reporters list, run 'docker run -t --rm -v DIRECTORY:/data riversafe/eze-cli housekeeping create-local-config' to create"
            raise EzeConfigError(error_message)
        return scan_config

    def get_plugin_config(self, plugin_name: str, scan_type: str = None, run_type: str = None) -> dict:
        """Gives plugin's configuration, and any custom config from a named scan or run type"""
        composite_config = {}
        [plugin_name, run_type] = extract_embedded_run_type(plugin_name, run_type)
        # step 1) clone default plugin config
        # (normal tool <ROOT>.<tool>)
        config_root = py_.get(self, "config", None)
        # step 2) append "custom named" scan config
        # (language tool <ROOT>.scan.<scan-type>.<tool>)
        scantype_root = py_.get(self, f"""config.scan.{scan_type}""", None)

        # (normal tool <ROOT>.<tool>)
        merge_from_root_base(config_root, composite_config, plugin_name)
        merge_from_root_base(scantype_root, composite_config, plugin_name)

        # look in flat {PLUGIN}_{RUN} key
        merge_from_root_flat(config_root, composite_config, plugin_name, run_type)
        merge_from_root_flat(scantype_root, composite_config, plugin_name, run_type)

        # look in nested {PLUGIN}.{RUN} key
        merge_from_root_nested(config_root, composite_config, plugin_name, run_type)
        merge_from_root_nested(scantype_root, composite_config, plugin_name, run_type)
        return composite_config


class PluginMeta(ABC):
    """Base class for all tool / reporter implementations"""

    SHORT_DESCRIPTION: str = ""
    INSTALL_HELP: str = ""
    MORE_INFO: str = ""
    LICENSE: str = "Unknown"
    VERSION_CHECK: dict = {
        "FROM_EXE": None,
        "FROM_MAVEN": None,
        "FROM_PIP": None,
        "FROM_EZE": False,
        "IGNORED_ERR_MESSAGES": [],
        "CONDITION": None,
    }
    EZE_CONFIG: dict = {}

    def _parse_config(self, config: dict) -> dict:
        """take raw config dict and normalise values, can be overridden for advanced behaviours"""
        parsed_config = get_config_keys(config, deepcopy(self.EZE_CONFIG))
        return parsed_config

    def __init__(self, config: dict = None):
        """constructor"""
        if config is None:
            config = {}
        self.config = self._parse_config(config)

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
    def install_help(cls) -> str:
        """Returns self help instructions how to install the tool"""
        return cls.INSTALL_HELP

    @classmethod
    def check_installed(cls) -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed

        Takes a tool/reporter class with following fields

        VERSION_CHECK.FROM_EXE
        VERSION_CHECK.FROM_MAVEN
        VERSION_CHECK.CONDITION semantic_version.SimpleSpec statement aka >=6.0
        """
        version: str = cls._get_version()
        condition: str = py_.get(cls.VERSION_CHECK, "CONDITION")
        if condition:
            try:
                version6_or_above = semantic_version.SimpleSpec(condition)
                parsed_version = semantic_version.Version(version)
                if not version6_or_above.match(parsed_version):
                    return ""
            except ValueError:
                pass
        return version

    @classmethod
    def _get_version(cls) -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        exe_to_check: str = py_.get(cls.VERSION_CHECK, "FROM_EXE")
        maven_package: str = py_.get(cls.VERSION_CHECK, "FROM_MAVEN")
        pip_package: str = py_.get(cls.VERSION_CHECK, "FROM_PIP")
        use_eze_version: bool = py_.get(cls.VERSION_CHECK, "FROM_EZE")
        ignored_err_messages: list = py_.get(cls.VERSION_CHECK, "IGNORED_ERR_MESSAGES")

        if pip_package and exe_to_check:
            return detect_pip_executable_version(pip_package, exe_to_check)
        if pip_package and not exe_to_check:
            raise EzeError("VERSION_CHECK.FROM_PIP requires VERSION_CHECK.FROM_EXE")
        if maven_package:
            return extract_version_from_maven(maven_package)
        if exe_to_check:
            return extract_cmd_version(shlex.split(exe_to_check), ignored_err_messages)
        if use_eze_version:
            return __version__
