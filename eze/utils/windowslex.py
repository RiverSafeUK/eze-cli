"""Windowslex helpers, shlex functions equivalent for Windows
"""

import re


def join(split_command):
    """Return a shell-escaped string from *split_command*."""
    return " ".join(quote(arg) for arg in split_command)


_find_unsafe = re.compile(r"[^\w@%+=:,./-]", re.ASCII).search


def quote(s):
    """Return a shell-escaped version of the string *s*."""
    if not s:
        return '""'
    if _find_unsafe(s) is None:
        return s

    # use single quotes, and put single quotes into double quotes
    # the string $'b is then quoted as '$'"'"'b'
    return '"' + s.replace('"', '"\'"\'"') + '"'
