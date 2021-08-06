"""
Entry point for command line interface
"""
import asyncio

import click

from eze import __version__
from eze.cli.commands.housekeeping_commands import housekeeping_group
from eze.cli.commands.language_commands import languages_group
from eze.cli.commands.reporter_commands import reporters_group
from eze.cli.commands.tool_commands import tools_group
from eze.cli.commands.test_remote_commands import test_remote_commands
from eze.cli.utils.command_helpers import base_options, pass_state
from eze.cli.utils.config import has_local_config
from eze.core.engine import EzeCore
from eze.core.language import LanguageManager
from eze.core.reporter import ReporterManager
from eze.core.tool import ToolManager
from eze.utils.package import get_plugins

# see https://click.palletsprojects.com/en/7.x/api/#click.Context
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__)
@click.pass_context
def cli(ctx) -> None:
    """Eze Command line interface"""

    # initialise plugins
    installed_plugins = get_plugins()
    LanguageManager.set_instance(installed_plugins)
    ToolManager.set_instance(installed_plugins)
    ReporterManager.set_instance(installed_plugins)


@click.command("test")
@base_options
@pass_state
@click.option(
    "--scan-type",
    "-s",
    help="named custom scan type to run aka production can include run type aka 'safety:test-only'",
    required=False,
)
@click.option(
    "--force-autoscan/--dont-force-autoscan",
    help="Forces language autoscan and creation of new .ezerc.toml",
    default=False,
)
def test_command(state, config_file: str, scan_type: str, force_autoscan: bool) -> None:
    """Eze run scan"""
    eze_core = EzeCore.get_instance()
    build_ezerc = not has_local_config() or force_autoscan
    asyncio.run(eze_core.run_scan(scan_type, build_ezerc))


cli.add_command(housekeeping_group)
cli.add_command(tools_group)
cli.add_command(reporters_group)
cli.add_command(languages_group)
cli.add_command(test_command)
cli.add_command(test_remote_commands)
