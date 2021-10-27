"""
Singleton Class for storing Global Eze Config

This takes multiple TOML files

See table for reason why toml not json/yaml was chosen,
also it's what all the cool rust and python projects use
https://www.python.org/dev/peps/pep-0518/#overview-of-file-formats-considered

Also handles debug mode
(TODO: once logging plumbed in, look into debugging / log levels elsewhere)
"""
import json
from pydash import py_
import click
import toml

from pathlib import Path

from eze.utils.io import load_toml, ClickManagedFileAccessError


class ConfigException(Exception):
    """Extended exception for all config handling"""

    def __init__(self, message: str) -> None:
        """Constructor"""
        super().__init__(message)
        self.message = message


def extract_embedded_run_type(plugin_name: str, run_type: str = None) -> tuple:
    """extracts any run_type embedded into plugin_name, split and put into plugin_name / run_type"""
    if ":" in plugin_name and not run_type:
        bits = plugin_name.split(":", 1)
        plugin_name = bits[0]
        run_type = bits[1]
    if "_" in plugin_name and not run_type:
        bits = plugin_name.split("_", 1)
        plugin_name = bits[0]
        run_type = bits[1]
    return [plugin_name, run_type]


class PluginConfigField:
    def __init__(self, key: str, field_config: dict) -> None:
        self.key: str = key
        self.required: bool = field_config.get("required", False)
        self.type: object = field_config.get("type", str)
        # if not set, default value
        self.default: object = field_config.get("default")
        # sometimes example value isn't descriptive for help text
        self.default_help_value: object = field_config.get("default_help_value", self.default)
        # help text
        self.help_text: str = field_config.get("help_text", "")
        # example value
        self.help_example: object = field_config.get("help_example", "")

    def get_default_example(self) -> str:
        """gets example text"""
        if self.type is bool:
            return "true / false"
        if self.type is str:
            return '"..."'
        if self.type is list:
            return '["..."]'
        return "..."


def get_config_keys(raw_config: dict, fields_config: dict, config: dict = None) -> dict:
    """helper : takes raw config dict returns parsed config"""
    if not config:
        config = {}

    for key in fields_config:
        field_config: dict = fields_config[key]
        plugin_field: PluginConfigField = PluginConfigField(key, field_config)
        config[key] = get_config_key(raw_config, key, plugin_field.type, plugin_field.default)
        if plugin_field.required and not config[key]:
            error_message: str = f"required param '{key}' missing from configuration"
            if plugin_field.help_text:
                error_message += "\n" + plugin_field.help_text
            raise ConfigException(error_message)
    return config


def get_config_key(config: dict, key: str, value_type: object, default=False):
    """helper : takes raw config dict and get key or default"""
    if key in config:
        if isinstance(config[key], value_type):
            return config[key]
        if value_type is list and isinstance(config[key], str):
            # if want list and str given, wrap str as list
            return [config[key]]
    return default


def create_config_help(tool_name: str, plugin_fields_config: dict, common_fields_config: dict = None):
    """helper : given config will create help html"""
    config_help: str = f"""[{tool_name}]\n"""
    config_help += _create_config_help(plugin_fields_config)
    if common_fields_config:
        config_help += f"""\n# Common Tool Config\n\n"""
        config_help += _create_config_help(common_fields_config)
    return config_help


def _create_config_help(fields_config: dict):
    """helper : given config keys will create help for fields"""
    config_help: str = ""
    for key in fields_config:
        field_config = fields_config[key]
        plugin_field: PluginConfigField = PluginConfigField(key, field_config)
        field_config_help = (
            f"{plugin_field.key} {plugin_field.type.__name__}{'' if plugin_field.required else ' [OPTIONAL]'}\n"
        )
        if plugin_field.help_text:
            field_config_help += plugin_field.help_text + "\n"
        if plugin_field.default_help_value:
            field_config_help += f"default value: \n"
            field_config_help += f"  {plugin_field.key} = {json.dumps(plugin_field.default_help_value, default=vars)}\n"
        field_config_help = "# " + "\n# ".join(field_config_help.split("\n")) + "\n"
        if plugin_field.help_example:
            field_config_help += f"{plugin_field.key} = {json.dumps(plugin_field.help_example, default=vars)}\n"
        else:
            field_config_help += f"{plugin_field.key} = {plugin_field.get_default_example()}\n\n"
        field_config_help += "\n"
        config_help += field_config_help
    return config_help


class EzeConfig:
    """Singleton Class for accessing and merging multiple config files"""

    _instance = None
    debug_mode: bool = False

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
            load_toml(local_config)
            return True
        except toml.TomlDecodeError:
            return True
        except ClickManagedFileAccessError:
            return False

    @staticmethod
    def set_eze_config(external_file: str = None):
        """get the cached eze config

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

        if EzeConfig.debug_mode:
            print(
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
            print("EzeConfig unable to get config before it is setup")
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
                    self._add_config(config_file)
                    continue
                parsed_config = load_toml(config_file)
                self._add_config(parsed_config)
            except ClickManagedFileAccessError:
                if EzeConfig.debug_mode:
                    print(f"-- [CONFIG ENGINE] skipping file '{config_file}' as not found")
                continue
            except toml.TomlDecodeError as err:
                print(
                    f"-- [CONFIG ENGINE] Error: skipping file '{config_file}' as toml is corrupted, message: '{err.msg}' (line {err.lineno})"
                )
                continue

    def get_scan_config(self, scan_type: str = None) -> dict:
        """Gives scan's configuration, defaults to standard scan, but can be named scan"""
        scan_config = {}
        # clone default plugin config
        if "scan" in self.config:
            self._add_config(self.config["scan"], scan_config)
        # append custom named scan config
        if "scan" in self.config and scan_type in self.config["scan"]:
            named_scan_config = self.config["scan"][scan_type]
            self._add_config(named_scan_config, scan_config)

        # Warnings for corrupted config
        if "tools" not in scan_config and "languages" not in scan_config:
            error_message = "The ./ezerc config missing required scan.tools/languages list, run 'eze housekeeping create-local-config' to create"
            raise click.ClickException(error_message)

        if "reporters" not in scan_config:
            error_message = (
                "The ./ezerc config missing scan.reporters list, run 'eze housekeeping create-local-config' to create"
            )
            raise click.ClickException(error_message)
        return scan_config

    def get_plugin_config(
        self, plugin_name: str, scan_type: str = None, run_type: str = None, parent_container: str = None
    ) -> dict:
        """Gives plugin's configuration, and any custom config from a named scan or run type"""
        composite_config = {}
        [plugin_name, run_type] = extract_embedded_run_type(plugin_name, run_type)
        # step 1) clone default plugin config
        # (normal tool <ROOT>.<tool>)
        config_root = py_.get(self, f"""config""", None)
        # step 2) clone default plugin config
        # (language tool <ROOT>.<language>.<tool>)
        language_root = py_.get(self, f"""config.{parent_container}""", None)
        # step 3) append "custom named" scan config
        # (language tool <ROOT>.scan.<scan-type>.<tool>)
        scantype_root = py_.get(self, f"""config.scan.{scan_type}""", None)

        # (normal tool <ROOT>.<tool>)
        self._add_config_from_root_base(config_root, composite_config, plugin_name, run_type)
        self._add_config_from_root_base(language_root, composite_config, plugin_name, run_type)
        self._add_config_from_root_base(scantype_root, composite_config, plugin_name, run_type)

        # look in flat {PLUGIN}_{RUN} key
        self._add_config_from_root_flat(config_root, composite_config, plugin_name, run_type)
        self._add_config_from_root_flat(language_root, composite_config, plugin_name, run_type)
        self._add_config_from_root_flat(scantype_root, composite_config, plugin_name, run_type)

        # look in nested {PLUGIN}.{RUN} key
        self._add_config_from_root_nested(config_root, composite_config, plugin_name, run_type)
        self._add_config_from_root_nested(language_root, composite_config, plugin_name, run_type)
        self._add_config_from_root_nested(scantype_root, composite_config, plugin_name, run_type)
        return composite_config

    def _add_config_from_root_base(
        self, config_root: dict, current_config: dict, plugin_name: str, run_type: str = None
    ) -> dict:
        """Add to config based off <tool>, <tool>_<runtype>, and finally <tool>.<runtype>"""
        if not config_root:
            return
        # (normal tool <ROOT>.<tool>)
        if plugin_name in config_root:
            plugin_config = config_root[plugin_name]
            self._add_config(plugin_config, current_config)

    def _add_config_from_root_flat(
        self, config_root: dict, current_config: dict, plugin_name: str, run_type: str = None
    ) -> dict:
        """Add to config based off <tool>, <tool>_<runtype>, and finally <tool>.<runtype>"""
        if not config_root:
            return
        # look in flat {PLUGIN}_{RUN} key
        run_key = f"{plugin_name}_{run_type}"
        if run_key in config_root:
            plugin_flatrun_config = config_root[run_key]
            self._add_config(plugin_flatrun_config, current_config)

    def _add_config_from_root_nested(
        self, config_root: dict, current_config: dict, plugin_name: str, run_type: str = None
    ) -> dict:
        """Add to config based off <tool>, <tool>_<runtype>, and finally <tool>.<runtype>"""
        if not config_root:
            return
        # look in nested {PLUGIN}.{RUN} key
        if plugin_name in config_root:
            if run_type in config_root[plugin_name]:
                plugin_recursiverun_config = config_root[plugin_name][run_type]
                self._add_config(plugin_recursiverun_config, current_config)

    def _add_config(self, new_config: dict, target_config: dict = None):
        """adds new config, deep merging it into existing config"""
        target_config = target_config if target_config is not None else self.config

        for key in new_config:
            value = new_config[key]
            if key not in target_config:
                target_config[key] = value
            else:
                if not isinstance(value, dict):
                    target_config[key] = value
                else:
                    if key not in target_config:
                        target_config[key] = value
                    else:
                        self._add_config(value, target_config[key])
