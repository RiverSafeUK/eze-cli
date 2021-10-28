"""Common classes that commands can inherrit from to ensure common flags are passed through

Class based Technique copied from excellent examples in
https://github.com/pallets/click/issues/108
"""

from typing import Callable

import click

from eze.core.config import EzeConfig

"""spec https://click.palletsprojects.com/en/7.x/api/#click.File"""
FILE_TYPE = click.Path(exists=True, file_okay=True, dir_okay=False, readable=True, resolve_path=True)


class State(object):
    """Core State object shared by all commands, via @pass_state decorator"""

    def __init__(self):
        """Constructor"""
        self.config = None
        self.debug = False


pass_state = click.make_pass_decorator(State, ensure=True)


def config_option(f):
    """decorator from debug --config-file/-c option"""

    def callback(ctx, param, value):
        """option callback"""
        state = ctx.ensure_object(State)
        state.config = EzeConfig.refresh_ezerc_config(value)
        return value

    return click.option(
        "--config-file",
        "-c",
        type=FILE_TYPE,
        help="Pass external configuration file to Eze Cli",
        default=None,
        required=False,
        callback=callback,
    )(f)


def debug_option(f):
    """decorator from debug --debug/--no-debug option"""

    def callback(ctx, param, value):
        """option callback"""
        state = ctx.ensure_object(State)
        state.debug = value
        EzeConfig.debug_mode = value
        return value

    return click.option(
        "--debug/--no-debug", expose_value=False, help="Enables or disables debug mode", callback=callback
    )(f)


def base_options(wrapped_func: Callable):
    """Base debug and config options"""
    wrapped_func = config_option(wrapped_func)
    wrapped_func = debug_option(wrapped_func)
    return wrapped_func
