"""CLI reporters command"""
import sys

import click

from eze.cli.utils.command_helpers import debug_option
from eze.core.reporter import ReporterManager


@click.group("reporters")
@debug_option
def reporters_group():
    """container for reporter commands"""


@click.command("list", short_help="List the available reporters")
@click.option("--include-help/--exclude-help", default=False, help="adds all tools documentation")
@debug_option
def list_command(include_help: bool) -> None:
    """
    list available reporters
    """
    reporter_manager: ReporterManager = ReporterManager.get_instance()
    reporter_manager.print_reporters_list()
    if include_help:
        reporter_manager.print_reporters_help()


@click.command("help", short_help="List the help for a given reporter")
@click.argument("reporter", required=True)
@debug_option
def help_command(reporter: str) -> None:
    """
    display help for selected reporter
    """
    reporter_manager = ReporterManager.get_instance()
    if reporter not in reporter_manager.reporters:
        click.echo(f"Could not find reporter '{reporter}', use 'eze reporters list' to get available reporters")
        sys.exit(1)
    reporter_manager.print_reporter_help(reporter)


reporters_group.add_command(list_command)
reporters_group.add_command(help_command)
