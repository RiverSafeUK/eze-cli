# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,invalid-name
import shlex
from unittest import mock

import pytest
from pydash import trim

from tests.__test_helpers__.mock_helper import mock_run_cmd
from eze.utils.cli import (
    _check_output_corrupt,
    _extract_version,
    _extract_executable,
    build_cli_command,
    extract_leading_number,
    run_cmd,
    EzeExecutableNotFoundError,
    cmd_exists,
    run_cli_command,
    extract_version_from_maven,
    detect_pip_command,
    detect_pip_executable_version,
)
from eze.utils.language.java import ignore_groovy_errors


def test_ignore_groovy_errors__remove_groovy_messages():
    test_input = """WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by com.google.inject.internal.cglib.core.$ReflectUtils$1 (file:/usr/share/maven/lib/guice.jar) to method java.lang.ClassLoader.defineClass(java.lang.String,byte[],int,int,java.security.ProtectionDomain)
WARNING: Please consider reporting this to the maintainers of com.google.inject.internal.cglib.core.$ReflectUtils$1
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release"""
    output = ignore_groovy_errors(test_input)
    assert output == []


def test_ignore_groovy_errors__keep_non_groovy_messages():
    test_input = """'safety' is not recognized as an internal or external command, operable program or batch file."""
    output = ignore_groovy_errors(test_input)
    assert output == [test_input]

