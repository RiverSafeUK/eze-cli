# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,unused-argument
import os
import pathlib
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from eze.utils.io import (
    get_absolute_filename,
    pretty_print_json,
    load_json,
    xescape,
    load_toml,
    write_json,
    normalise_linux_file_path,
    normalise_file_paths,
    is_windows_os,
    normalise_windows_regex_file_path,
    delete_file,
    exit_app,
    parse_json,
)
from eze.utils.error import EzeFileAccessError, EzeFileParsingError
from tests.__fixtures__.fixture_helper import get_path_fixture


def setup_module(self):
    """Clean up temp folder"""
    eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
    shutil.rmtree(eze_temp_folder, ignore_errors=True)


def teardown_module(self):
    pass


class FakePermissionError(PermissionError):
    filename = "some-mocked-file.json"


class DummyClass:
    """Dummy Class"""

    def __init__(self):
        """constructor"""
        self.field1 = "should appear"
        self.field2 = "should appear"

    def func_should_not_appear(self):
        """dummy func"""
        return "foo"


def test_normalise_file_paths():
    # Given
    test_input = [
        "hello/world.json",
        "hello\\world.json",
        "hello\\mutiple\\world.json",
    ]
    expected_output = ["hello/world.json", "hello/world.json", "hello/mutiple/world.json"]

    # When
    output = normalise_file_paths(test_input)

    # Then
    assert output == expected_output


def test_normalise_file_path__forward():
    # Given
    test_input = "hello/world.json"
    expected_output = "hello/world.json"

    # When
    output = normalise_linux_file_path(test_input)

    # Then
    assert output == expected_output


def test_normalise_file_path__back():
    # Given
    test_input = "hello\\world.json"
    expected_output = "hello/world.json"

    # When
    output = normalise_linux_file_path(test_input)

    # Then
    assert output == expected_output


def test_normalise_windows_regex_file_path():
    # Given
    test_input = "hell/is_windows_paths/world.json"
    # WARNING: Yes this number of slashes is correct / === \\\\
    expected_output = "hell\\\\is_windows_paths\\\\world.json"

    # When
    output = normalise_windows_regex_file_path(test_input)

    # Then
    assert output == expected_output


@mock.patch("eze.utils.io.os.name", "nt")
def test_is_windows_os__windows_case():
    # Given
    expected_output = True
    # When
    output = is_windows_os()
    # Then
    assert output == expected_output


@mock.patch("eze.utils.io.os.name", "posix")
def test_is_windows_os__linux_case():
    # Given
    expected_output = False
    # When
    output = is_windows_os()
    # Then
    assert output == expected_output


@pytest.mark.skipif(sys.platform != "win32", reason="does not run on Linux")
def test_get_absolute_filename__absolute_url_win():
    """Test normal case for when Bash cannot find file"""

    expected_output = Path("C:\\dev\\path.json")
    test_input = "C:\\dev\\path.json"

    output = get_absolute_filename(test_input)
    assert output == expected_output


@pytest.mark.skipif(sys.platform == "win32", reason="does not run on Windows")
def test_get_absolute_filename__absolute_url_linux():
    """Test normal case for when Bash cannot find file"""

    expected_output = Path("/dev/path.json")
    test_input = "/dev/path.json"

    output = get_absolute_filename(test_input)
    assert output == expected_output


def test_get_absolute_filename__relative_url():
    """Test normal case for when Bash cannot find file"""

    expected_output = Path(Path(os.getcwd()).joinpath("path.json"))
    test_input = "path.json"

    output = get_absolute_filename(test_input)
    assert output == expected_output


def test_pretty_print_json():
    """Test normal case, especially tests if can seralise classes"""

    expected_output = """{
  "bool_is": true,
  "class_is": {
    "field1": "should appear",
    "field2": "should appear"
  },
  "foo": "bar",
  "hello": 1,
  "list_is": []
}"""
    test_input = dict({"hello": 1, "foo": "bar", "bool_is": True, "list_is": [], "class_is": DummyClass()})

    output = pretty_print_json(test_input)
    assert output == expected_output


def test_parse_json__happy_path():
    expected_output = {"Iam": "json", "someArray": [], "someInt": 1, "someNull": None, "someObject": {}}
    input_json = pretty_print_json(expected_output)
    output = parse_json(input_json)

    assert output == expected_output


def test_parse_json__sad_path__ab_898_json_error():
    input_json = "NOT REAL JSON"
    expected_error = "Unable to parse JSON fragment"

    with pytest.raises(EzeFileParsingError) as raised_error:
        parse_json(input_json)
    # Then
    assert expected_error in str(raised_error.value)


def test_load_json__happy_path():
    sample_json_path = get_path_fixture("__fixtures__/io/sample_json.json")
    expected_output = {"Iam": "json", "someArray": [], "someInt": 1, "someNull": None, "someObject": {}}
    output = load_json(sample_json_path)

    assert output == expected_output


def test_load_json__sad_path__ab_898_json_error():
    sample_json_path = get_path_fixture("__fixtures__/io/sample_broken_json.json")
    expected_error = "Unable to parse JSON file"

    with pytest.raises(EzeFileParsingError) as raised_error:
        load_json(str(sample_json_path))
    # Then
    assert expected_error in str(raised_error.value)


@mock.patch("eze.utils.io.open", side_effect=FakePermissionError())
def test_load_json__sad_path__ab_688_permission_error(mock_write_text):
    # Given
    input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "report.json"
    expected_error = "Eze cannot access 'some-mocked-file.json', Permission was denied"

    with pytest.raises(EzeFileAccessError) as raised_error:
        load_json(input_report_location)
    # Then
    assert str(expected_error) == str(raised_error.value)


def test_load_json__sad_path__empty_case(tmp_path):
    json_file = tmp_path / "path/test_file.json"
    json_file.parent.mkdir()
    json_file.touch()

    expected = []
    sample = load_json(json_file)
    assert expected == sample
    os.remove(json_file)


def test_write_json():
    """Test normal case, can write json into python object"""

    # Given
    input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-local-test_io_write_json.json"
    input_vo = [1, 2, 3, 4, 5]

    # When
    written_location = write_json(input_report_location, input_vo)

    # Then
    output = load_json(written_location)
    assert written_location == input_report_location


@mock.patch("eze.utils.io.os.makedirs", side_effect=FakePermissionError())
def test_write_json__ab_688_makedirs_exception(mock_make_dirs):
    """Test irregular case, can't create folder"""

    # Given
    input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp"
    input_vo = [1, 2, 3, 4, 5]
    expected_error = "Eze cannot create folder 'some-mocked-file.json', Permission was denied"

    with pytest.raises(EzeFileAccessError) as raised_error:
        write_json(input_report_location / "report.json", input_vo)

    # Then
    assert str(expected_error) == str(raised_error.value)


@mock.patch("eze.utils.io.open", side_effect=FakePermissionError())
def test_write_json__ab_688_write_exception(mock_write_text):
    """ab-688: Test irregular case, cant write text file"""

    # Given
    input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "report.json"
    input_vo = [1, 2, 3, 4, 5]
    expected_error = "Eze cannot write 'some-mocked-file.json', Permission was denied"

    with pytest.raises(Exception) as raised_error:
        write_json(input_report_location, input_vo)
    # Then
    assert str(expected_error) == str(raised_error.value)


def test_load_toml():
    """Test normal case, can toml and seralise dict into python object"""

    sample_toml_path = get_path_fixture("__fixtures__/io/sample_toml.toml")

    expected_output = {
        "Iam": "json",
        "someArray": [],
        "someInt": 1,
        "someObject": {"helloworld": 1, "nested": {"helloworld_nested": 1}},
    }
    output = load_toml(sample_toml_path)

    assert output == expected_output


def test_xescape__empty():
    """Test empty case"""

    test_input = None
    expected_output = ""
    output = xescape(test_input)

    assert output == expected_output


def test_xescape__std():
    """Test normal case"""

    test_input = '\\" <evil-xml-tag/>'
    expected_output = "&#92;&quot; &lt;evil-xml-tag/&gt;"
    output = xescape(test_input)

    assert output == expected_output


def test_xescape__zero():
    """Test zero case"""

    test_input = 0
    expected_output = "0"
    output = xescape(test_input)

    assert output == expected_output


def test_delete_file(tmp_path):
    # Given
    file_name = tmp_path / "dir/test_file.txt"
    file_name.parent.mkdir()
    file_name.touch()
    assert os.path.exists(file_name) == 1

    # When
    delete_file(file_name)

    # Then
    assert os.path.exists(file_name) == 0


def test_exit_app():
    expected_error = "There was an error"
    with pytest.raises(Exception, match=expected_error) as raised_error:
        exit_app(expected_error)
    assert raised_error.value.message == expected_error
