"""Module for storing all eze Error classes"""
import click


class EzeError(click.ClickException):
    """Base Error Class for all Eze"""

    pass


class EzeFileError(EzeError):
    """File system Error Class for all Eze"""

    pass


class EzeFileParsingError(EzeFileError):
    """File Parsing Error Class for all Eze"""

    pass


class EzeFileAccessError(EzeFileError):
    """File Accesses Error Class for all Eze"""

    pass


class EzeNetworkingError(EzeError):
    """Networking Error Class for all Eze"""

    pass


class EzeConfigError(EzeError):
    """Config Error Class for all Eze"""

    pass


class EzeExecutableError(EzeError):
    """Executable Error Class for all Eze (when sub commands called)"""

    pass


class EzeExecutableNotFoundError(EzeExecutableError):
    """Executable Not Found Error Class for all Eze (when sub commands called)"""

    pass


class EzeExecutableStdErrError(EzeExecutableError):
    """Executable Outputs to StdErr Error Class for all Eze (when sub commands called)"""

    pass
