"""Logging refactor"""
import click


class LogLevel:
    """Singleton Class for sending logging to terminal stdout and stderr"""

    NONE: int = 3
    ERROR: int = 2
    LOG: int = 1
    DEBUG: int = 0
    _level: int = LOG
    _reprint_message_length: int = 0
    _status_messages_enabled: bool = True

    @staticmethod
    def get_level():
        """Get previously set global logging"""
        return LogLevel._level

    @staticmethod
    def set_level(value: int):
        """Get previously set global logging"""
        LogLevel._level = value

    @staticmethod
    def print_status_messages(value: bool = True):
        """set if status messages should be used (aka prints that overwrite one another, aka second counts etc)"""
        LogLevel._status_messages_enabled = value

    @staticmethod
    def reset_instance():
        """Reset the global logging"""
        LogLevel._level = LogLevel.LOG
        LogLevel._reprint_message_length = 0
        LogLevel._status_messages_enabled = True

    @staticmethod
    def log_error(log_text: str) -> None:
        """prints to stderr on error cases with the colour red"""
        if LogLevel.get_level() <= LogLevel.ERROR:
            clear_status_message()
            click.secho(log_text, fg="red", err=True)

    @staticmethod
    def log(log_text: str) -> None:
        """Print to stdout"""
        if LogLevel.get_level() <= LogLevel.LOG:
            clear_status_message()
            click.secho(log_text, fg="bright_white")

    @staticmethod
    def log_debug(log_text: str) -> None:
        """Prints to stdout only if LogLevel.level is above LogLevel.DEBUG"""
        if LogLevel.get_level() <= LogLevel.DEBUG:
            clear_status_message()
            click.secho(log_text, fg="white")

    @staticmethod
    def status_message(log_text: str):
        """Status message which overwrites previous status message, aka for count downs or second timers"""
        if not LogLevel._status_messages_enabled:
            return
        print(LogLevel._reprint_message_length * " ", end="\r")
        print(log_text, end="\r")
        LogLevel._reprint_message_length = len(log_text)

    @staticmethod
    def clear_status_message():
        """Delete last status_message, works cross os"""
        if not LogLevel._status_messages_enabled or LogLevel._reprint_message_length == 0:
            return
        print(LogLevel._reprint_message_length * " ", end="\r")
        LogLevel._reprint_message_length = 0


def log_error(log_text: str) -> None:
    """prints to stderr on error cases with the colour red"""
    LogLevel.log_error(log_text)


def log(log_text: str) -> None:
    """Print to stdout"""
    LogLevel.log(log_text)


def log_debug(log_text: str) -> None:
    """Prints to stdout only if LogLevel.level is above LogLevel.DEBUG"""
    LogLevel.log_debug(log_text)


def status_message(log_text: str):
    """Delete last line, and prints new line"""
    LogLevel.status_message(log_text)


def clear_status_message():
    """Delete last status_message, works cross os"""
    LogLevel.clear_status_message()
