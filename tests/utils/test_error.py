# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,invalid-name
from eze.utils.error import (
    EzeError,
    EzeFileAccessError,
    EzeNetworkingError,
    EzeFileError,
    EzeFileParsingError,
    EzeExecutableError,
    EzeExecutableStdErrError,
    EzeExecutableNotFoundError,
    EzeConfigError,
)

from click import ClickException


def test_EzeError__string_coercion():
    test_input = EzeError("helloworld")
    assert f"{test_input}" == "helloworld"
    assert isinstance(test_input, ClickException)


def test_EzeConfigError__string_coercion():
    test_input = EzeConfigError("helloworld")
    assert f"{test_input}" == "helloworld"
    assert isinstance(test_input, EzeError)
    assert isinstance(test_input, ClickException)


def test_EzeFileError__string_coercion():
    test_input = EzeFileError("helloworld")
    assert f"{test_input}" == "helloworld"
    assert isinstance(test_input, EzeError)
    assert isinstance(test_input, ClickException)


def test_EzeFileParsingError__string_coercion():
    test_input = EzeFileParsingError("helloworld")
    assert f"{test_input}" == "helloworld"
    assert isinstance(test_input, EzeFileError)
    assert isinstance(test_input, EzeError)
    assert isinstance(test_input, ClickException)


def test_EzeFileAccessError__string_coercion():
    test_input = EzeFileAccessError("helloworld")
    assert f"{test_input}" == "helloworld"
    assert isinstance(test_input, EzeFileError)
    assert isinstance(test_input, EzeError)
    assert isinstance(test_input, ClickException)


def test_EzeNetworkingError__string_coercion():
    test_input = EzeNetworkingError("helloworld")
    assert f"{test_input}" == "helloworld"
    assert isinstance(test_input, EzeError)
    assert isinstance(test_input, ClickException)


def test_EzeExecutableError__string_coercion():
    test_input = EzeExecutableError("helloworld")
    assert f"{test_input}" == "helloworld"
    assert isinstance(test_input, EzeError)
    assert isinstance(test_input, ClickException)


def test_EzeExecutableStdErrError__string_coercion():
    test_input = EzeExecutableStdErrError("helloworld")
    assert f"{test_input}" == "helloworld"
    assert isinstance(test_input, EzeExecutableError)
    assert isinstance(test_input, EzeError)
    assert isinstance(test_input, ClickException)


def test_EzeExecutableNotFoundError__string_coercion():
    test_input = EzeExecutableNotFoundError("helloworld")
    assert f"{test_input}" == "helloworld"
    assert isinstance(test_input, EzeExecutableError)
    assert isinstance(test_input, EzeError)
    assert isinstance(test_input, ClickException)
