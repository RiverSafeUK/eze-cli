"""Logging refactor"""
import click


class LogLevel:
    """Singleton Class for accessing and merging multiple config files"""

    NONE: int = 3
    ERROR: int = 2
    LOG: int = 1
    DEBUG: int = 0
    level: int = LOG


def log_error(log_text: str) -> None:
    """prints to stderr on error cases with the colour red"""
    if LogLevel.level <= LogLevel.ERROR:
        click.secho(log_text, fg="red", err=True)


def log(log_text: str) -> None:
    """Print to stdout"""
    if LogLevel.level <= LogLevel.LOG:
        click.secho(log_text, fg="bright_white")


def log_debug(log_text: str) -> None:
    """Prints to stdout only if LogLevel.level is above LogLevel.DEBUG"""
    if LogLevel.level <= LogLevel.DEBUG:
        click.secho(log_text, fg="white")
