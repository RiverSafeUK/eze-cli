# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,unused-argument
from eze.utils.log import log, log_debug, log_error, LogLevel, status_message, clear_status_message
from tests.__test_helpers__.mock_helper import mock_print, unmock_print, mock_print_stderr, unmock_print_stderr


def teardown_function(function):
    """Teardown function"""
    unmock_print()
    unmock_print_stderr()
    LogLevel.reset_instance()


def test_log():
    # Given
    mocked_print_output = mock_print()
    mocked_print_output_stderr = mock_print_stderr()
    expected_output = "Echo 123\n"
    expected_output_stderr = ""

    # When
    test_input = "Echo 123"
    log(test_input)

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output
    output_stderr = mocked_print_output_stderr.getvalue()
    assert output_stderr == expected_output_stderr


def test_log_debug__in_debug_mode():
    # Given
    LogLevel.set_level(LogLevel.DEBUG)
    mocked_print_output = mock_print()
    mocked_print_output_stderr = mock_print_stderr()
    expected_output = "Echo 123\n"
    expected_output_stderr = ""

    # When
    test_input = "Echo 123"
    log_debug(test_input)

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output
    output_stderr = mocked_print_output_stderr.getvalue()
    assert output_stderr == expected_output_stderr


def test_log_debug__not_in_debug_mode():
    # Given
    mocked_print_output = mock_print()
    mocked_print_output_stderr = mock_print_stderr()
    expected_output = ""
    expected_output_stderr = ""

    # When
    test_input = "Echo 123"
    log_debug(test_input)

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output
    output_stderr = mocked_print_output_stderr.getvalue()
    assert output_stderr == expected_output_stderr


def test_log_error():
    # Given
    mocked_print_output = mock_print()
    mocked_print_output_stderr = mock_print_stderr()
    expected_output = ""
    expected_output_stderr = "Echo 123\n"

    # When
    test_input = "Echo 123"
    log_error(test_input)

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output
    output_stderr = mocked_print_output_stderr.getvalue()
    assert output_stderr == expected_output_stderr


def test_status_message():
    # Given
    mocked_print_output = mock_print()
    mocked_print_output_stderr = mock_print_stderr()
    # aka print / clear / print
    expected_output = "\rEcho 123\r        \rEcho 123\r"
    expected_output_stderr = ""

    # When
    test_input = """Echo 123"""
    status_message(test_input)
    status_message(test_input)

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output
    output_stderr = mocked_print_output_stderr.getvalue()
    assert output_stderr == expected_output_stderr


def test_clear_status_message():
    # Given
    mocked_print_output = mock_print()
    mocked_print_output_stderr = mock_print_stderr()
    # aka print / clear
    expected_output = "\rEcho 123\r        \r"
    expected_output_stderr = ""

    # When
    test_input = """Echo 123"""
    status_message(test_input)
    clear_status_message()

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output
    output_stderr = mocked_print_output_stderr.getvalue()
    assert output_stderr == expected_output_stderr
