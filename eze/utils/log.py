"""Logging refactor"""
import click


def log(log_text: str) -> None:
    """Print to stdout"""
    click.secho(log_text, fg="bright_white")


def log_debug(log_text: str) -> None:
    """Prints to stdout only if EzeConfig.debug_mode is True"""
    click.secho(log_text, fg="white")


def log_error(log_text: str) -> None:
    """prints to stderr on error cases with the colour red"""
    click.secho(log_text, fg="red", err=True)
