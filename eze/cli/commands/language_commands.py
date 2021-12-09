"""CLI languages command"""

import sys

import click

from eze.cli.utils.command_helpers import debug_option
from eze.core.language import LanguageManager
from eze.utils.log import log, log_debug, log_error


@click.group("languages")
@debug_option
def languages_group():
    """container for language commands"""


@click.command("list", short_help="List the available languages")
@click.option("--include-help/--exclude-help", default=False, help="adds all tools documentation")
@debug_option
def list_command(include_help: bool) -> None:
    """
    list available languages
    """

    language_manager = LanguageManager.get_instance()
    language_manager.print_languages_list()
    if include_help:
        language_manager.print_languages_help()


@click.command("help", short_help="List the help for a given language")
@click.argument("language", required=True)
@debug_option
def help_command(language: str) -> None:
    """
    display help for selected language
    """
    language_manager = LanguageManager.get_instance()
    if language not in language_manager.languages:
        log(f"Could not find language '{language}', use 'eze languages list' to get available languages")
        sys.exit(1)
    language_manager.print_language_help(language)


languages_group.add_command(list_command)
languages_group.add_command(help_command)
