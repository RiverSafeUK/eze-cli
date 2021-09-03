"""Utility module for obtaining user config for the eze app

Wraps EzeConfig so any CLI specific concerns can be handled here in abstraction
without poluting the Eze Core Libs
"""
from pathlib import Path

import click
import toml

from eze.core.config import EzeConfig
from eze.utils.io import load_toml, ClickManagedFileAccessError


def get_debug_mode() -> bool:
    """Get Eze's global debug mode"""
    return EzeConfig.debug_mode


def set_debug_mode(value: bool):
    """Set Eze's global debug mode"""
    EzeConfig.debug_mode = value


def get_eze_config() -> EzeConfig:
    """get cached config"""
    return EzeConfig.get_instance()


def get_global_config_filename() -> Path:
    """Path of global configuration file"""
    raw_path = click.get_app_dir("eze", roaming=False, force_posix=False)
    global_config_file = Path(raw_path) / "config.toml"
    return global_config_file


def get_local_config_filename() -> Path:
    """Path of local configuration file"""
    local_config_file = Path.cwd() / ".ezerc.toml"
    return local_config_file


def has_local_config() -> bool:
    """Is local .ezerc present"""
    try:
        local_config = get_local_config_filename()
        load_toml(local_config)
        return True
    except toml.TomlDecodeError:
        return True
    except ClickManagedFileAccessError:
        return False


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

    global_config_file = get_global_config_filename()
    local_config_file = get_local_config_filename()

    if get_debug_mode():
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
