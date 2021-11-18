# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,invalid-name
from eze.utils.error import (
    EzeError,
    EzeFileAccessError,
    EzeNetworkingError,
    EzeFileParsingError,
    EzeExecutableNotFoundError,
)


def test_EzeError__string_coercion():
    test_input = EzeError("helloworld")
    assert f"{test_input}" == "helloworld"


def test_EzeFileParsingError__string_coercion():
    test_input = EzeFileParsingError("helloworld")
    assert f"{test_input}" == "helloworld"


def test_EzeFileAccessError__string_coercion():
    test_input = EzeFileAccessError("helloworld")
    assert f"{test_input}" == "helloworld"


def test_EzeNetworkingError__string_coercion():
    test_input = EzeNetworkingError("helloworld")
    assert f"{test_input}" == "helloworld"


def test_EzeExecutableNotFoundError__string_coercion():
    test_input = EzeExecutableNotFoundError("helloworld")
    assert f"{test_input}" == "helloworld"
