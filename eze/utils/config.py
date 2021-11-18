"""Basic config helpers utils

helps with low level:
- the recursive merging of toml files
- merging object together ontop of one another

Actual logic inside EzeConfig
"""
import json

from eze.utils.error import EzeConfigError


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
            raise EzeConfigError(error_message)
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


def merge_from_root_base(config_root: dict, target_config: dict, plugin_name: str) -> dict:
    """Add to config based off xxx.<plugin_name>"""
    if not config_root:
        return
    # (normal tool <ROOT>.<tool>)
    if plugin_name in config_root:
        plugin_config = config_root[plugin_name]
        merge_configs(plugin_config, target_config)


def merge_from_root_flat(config_root: dict, target_config: dict, plugin_name: str, run_type: str = None) -> dict:
    """Add to config based off xxx.<plugin_name>_<runtype>"""
    if not config_root:
        return
    # look in flat {PLUGIN}_{RUN} key
    run_key = f"{plugin_name}_{run_type}"
    if run_key in config_root:
        plugin_flatrun_config = config_root[run_key]
        merge_configs(plugin_flatrun_config, target_config)


def merge_from_root_nested(config_root: dict, target_config: dict, plugin_name: str, run_type: str = None) -> dict:
    """Add to config based off xxx.<plugin_name>.<runtype>"""
    if not config_root:
        return
    # look in nested {PLUGIN}.{RUN} key
    if plugin_name in config_root:
        if run_type in config_root[plugin_name]:
            plugin_recursive_config = config_root[plugin_name][run_type]
            merge_configs(plugin_recursive_config, target_config)


def merge_configs(merge_config: dict, target_config: dict):
    """adds new config, deep merging it into existing config"""
    for key in merge_config:
        value = merge_config[key]
        if key not in target_config:
            target_config[key] = value
        else:
            if not isinstance(value, dict):
                target_config[key] = value
            else:
                if key not in target_config:
                    target_config[key] = value
                else:
                    merge_configs(value, target_config[key])
