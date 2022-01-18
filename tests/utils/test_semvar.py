# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from utils.semvar import is_semvar


def test_is_semvar__happy():
    # Given
    input_semvar = "4.4.4"
    # When
    output = is_semvar(input_semvar)
    # Then
    assert output is True


def test_is_semvar__sad():
    # Given
    input_semvar = "there are errors here"
    # When
    output = is_semvar(input_semvar)
    # Then
    assert output is False
