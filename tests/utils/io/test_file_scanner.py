import pytest

from tests.__test_helpers__.mock_helper import unmock_file_scanner, mock_file_scanner
from eze.utils.io.file_scanner import find_files_by_name, find_files_by_path


def teardown_function(function):
    unmock_file_scanner()


def test_find_files_by_path__happy():
    # Given
    mock_file_scanner()
    expected_output = ["src/thing.js"]
    test_output = find_files_by_path("src/.*")
    assert test_output == expected_output


def test_find_files_by_path__happy_but_empty():
    # Given
    mock_file_scanner()
    expected_output = []
    test_output = find_files_by_path("does-not-exist")
    assert test_output == expected_output


def test_find_files_by_path__sad_invalid_regex():
    # Given
    mock_file_scanner()
    with pytest.raises(Exception) as raised_error:
        test_output = find_files_by_path("*.py")
    assert raised_error.value.args[0] == "unable to parse regex '*.py' due to nothing to repeat"


def test_find_files_by_name__happy():
    # Given
    mock_file_scanner()
    expected_output = ["src/thing.js"]
    test_output = find_files_by_name(".+[.]js")
    assert test_output == expected_output


def test_find_files_by_name__happy_but_empty():
    # Given
    mock_file_scanner()
    expected_output = []
    test_output = find_files_by_name("does-not-exist")
    assert test_output == expected_output


def test_find_files_by_name__sad_invalid_regex():
    # Given
    mock_file_scanner()
    with pytest.raises(Exception) as raised_error:
        test_output = find_files_by_name("*.py")
    assert raised_error.value.args[0] == "unable to parse regex '*.py' due to nothing to repeat"
