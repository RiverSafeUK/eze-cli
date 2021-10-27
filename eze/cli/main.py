"""
Entry point for command line interface
"""

import click

from eze import __version__
from eze.cli.commands.housekeeping_commands import housekeeping_group
from eze.cli.commands.language_commands import languages_group
from eze.cli.commands.reporter_commands import reporters_group
from eze.cli.commands.tool_commands import tools_group
from eze.cli.commands.test_commands import test_remote_command, test_online_command, test_command
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


cli.add_command(housekeeping_group)
cli.add_command(tools_group)
cli.add_command(reporters_group)
cli.add_command(languages_group)
cli.add_command(test_command)
cli.add_command(test_online_command)
cli.add_command(test_remote_command)
