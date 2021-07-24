"""House keeping command list"""
import os
import pathlib

import click

from eze.cli.utils.command_helpers import debug_option
from eze.cli.utils.config import get_global_config_filename, get_local_config_filename
from eze.core.language import LanguageManager
from eze.core.reporter import ReporterManager
from eze.core.tool import ToolManager
from eze.utils.git import get_active_branch_name, get_active_branch_uri

DEFAULT_GLOABL_CONFIG_COPY = """
# ===================================
# TOOL GLOBAL CONFIG
# ===================================
[safety]
# Optional APIKEY
# By default it uses the open Python vulnerability database Safety DB, 
# but can be upgraded to use pyup.io's Safety API using the APIKEY option
# see https://github.com/pyupio/safety/blob/master/docs/api_key.md
# APIKEY: XXX-XXX 

# ===================================
# REPORTER GLOBAL CONFIG
# ===================================
[eze]
# WARNING: APIKEY should be kept in your global system config and not stored in version control .ezerc.toml
# it can also be specifed as the environment variable EZE_APIKEY
# APIKEY = xxx

# Required management console url
# as specified by eze management console "/profile" page
# CONSOLE_ENDPOINT = xxx
"""


@click.group("housekeeping")
@debug_option
def housekeeping_group():
    """container for miscellaneous house keeping commands"""


@click.command("create-local-config", short_help="create local config file")
@debug_option
def create_local_config_command():
    """creates a default config for a user in their local location"""
    click.echo(f"Auto generating a new .ezerc.toml")
    language_manager = LanguageManager.get_instance()
    language_manager = language_manager.create_local_ezerc_config()


@click.command("create-global-config", short_help="create global config file")
@debug_option
def create_global_config_command():
    """created a default config for a user in their global location"""
    global_config_location = get_global_config_filename()
    _create_config_file(global_config_location, DEFAULT_GLOABL_CONFIG_COPY)


@click.command("list-config", short_help="list the config file locations")
@debug_option
def list_locations_command():
    """created a default config for a user in their global location"""
    global_config_location = get_global_config_filename()
    local_config_location = get_local_config_filename()
    click.echo(f"Global configuration file: '{global_config_location}'")
    click.echo(f"Local configuration file: '{local_config_location}'")


def _create_config_file(config_location: pathlib.Path, copy: str) -> None:
    """Create the path to create the config file at and creates file"""
    if config_location.is_file():
        click.echo(f"unable to create config '{config_location}' as it already exists", err=True)
        return
    config_path = os.path.dirname(config_location)
    os.makedirs(config_path, exist_ok=True)
    handler = open(config_location, mode="w")
    handler.write(copy)
    handler.close()
    click.echo(f"Successfully written configuration file to '{config_location}'")


@click.command("get-repo", short_help="get current git repo folder is in")
@debug_option
def get_repo_command():
    """Utility function for detecting current git repo, supports HEAD checked out codebases on CI servers"""
    git_dir = os.getcwd()
    uri = get_active_branch_uri(git_dir)
    branch = get_active_branch_name(git_dir)
    click.echo(f"""Current Branch is uri:'{uri}' name:'{branch}'""")


@click.command("documentation", short_help="list all plugins installed and their documentation")
@click.option("--include-help/--exclude-help", default=False, help=f"adds all tools documentation")
@debug_option
def documentation_command(include_help: bool):
    """list all plugins (languages, tools, and reporters) then all their documentation"""
    click.echo(
        """Printing all eze plugins installed
======================="""
    )
    tool_manager: ToolManager = ToolManager.get_instance()
    reporter_manager: ReporterManager = ReporterManager.get_instance()
    tool_manager.print_tools_list()
    reporter_manager.print_reporters_list()
    if include_help:
        click.echo(
            """Printing all eze documentation
======================="""
        )
        tool_manager.print_tools_help()
        reporter_manager.print_reporters_help()


housekeeping_group.add_command(create_local_config_command)
housekeeping_group.add_command(create_global_config_command)
housekeeping_group.add_command(list_locations_command)
housekeeping_group.add_command(get_repo_command)
housekeeping_group.add_command(documentation_command)
