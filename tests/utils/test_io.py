# pylint: disable=missing-module-docstring,missing-class-docstring
import os
import pathlib
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

import click

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
)
from tests.__fixtures__.fixture_helper import get_path_fixture


def setup_module(module):
    """Clean up temp folder"""
    eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
    shutil.rmtree(eze_temp_folder, ignore_errors=True)


def teardown_module(module):
    print("teardown any state that was previously setup with a setup_module method.")


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
    input = [
        "hello/world.json",
        "hello\\world.json",
        "hello\\mutiple\\world.json",
    ]
    expected_output = ["hello/world.json", "hello/world.json", "hello/mutiple/world.json"]

    # When
    output = normalise_file_paths(input)

    # Then
    assert output == expected_output


def test_normalise_file_path__forward():
    # Given
    input = "hello/world.json"
    expected_output = "hello/world.json"

    # When
    output = normalise_linux_file_path(input)

    # Then
    assert output == expected_output


def test_normalise_file_path__back():
    # Given
    input = "hello\\world.json"
    expected_output = "hello/world.json"

    # When
    output = normalise_linux_file_path(input)

    # Then
    assert output == expected_output


def test_normalise_windows_regex_file_path():
    # Given
    input = "hell/is_windows_paths/world.json"
    # WARNING: Yes this number of slashes is correct / === \\\\
    expected_output = "hell\\\\is_windows_paths\\\\world.json"

    # When
    output = normalise_windows_regex_file_path(input)

    # Then
    assert output == expected_output


@mock.patch("eze.utils.io.os.name", "nt")
def test_is_windows_os__windows_case() -> bool:
    # Given
    expected_output = True
    # When
    output = is_windows_os()
    # Then
    assert output == expected_output


@mock.patch("eze.utils.io.os.name", "posix")
def test_is_windows_os__linux_case() -> bool:
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
    input = "C:\\dev\\path.json"

    output = get_absolute_filename(input)
    assert output == expected_output


@pytest.mark.skipif(sys.platform == "win32", reason="does not run on Windows")
def test_get_absolute_filename__absolute_url_linux():
    """Test normal case for when Bash cannot find file"""

    expected_output = Path("/dev/path.json")
    input = "/dev/path.json"

    output = get_absolute_filename(input)
    assert output == expected_output


def test_get_absolute_filename__relative_url():
    """Test normal case for when Bash cannot find file"""

    expected_output = Path(Path(os.getcwd()).joinpath("path.json"))
    input = "path.json"

    output = get_absolute_filename(input)
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
    input = dict({"hello": 1, "foo": "bar", "bool_is": True, "list_is": [], "class_is": DummyClass()})

    output = pretty_print_json(input)
    assert output == expected_output


def test_load_json():
    """Test normal case, can load and seralise json into python object"""

    sample_json_path = get_path_fixture("__fixtures__/io/sample_json.json")
    expected_output = {"Iam": "json", "someArray": [], "someInt": 1, "someNull": None, "someObject": {}}
    output = load_json(sample_json_path)

    assert output == expected_output


@mock.patch("eze.utils.io.os.makedirs", side_effect=PermissionError())
def test_write_json__makedirs_exception(mock_make_dirs):
    """Test irregular case, can't create folder"""

    # Given
    input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp"
    input_vo = [1, 2, 3, 4, 5]
    expected_error = click.ClickException(f"Eze can not access '{input_report_location}' as Permission was denied.")

    try:
        write_json(input_report_location / "report.json", input_vo)
    except Exception as e:
        raised_error = e

    # Then
    assert str(expected_error) == str(raised_error)


@mock.patch("eze.utils.io.open", side_effect=PermissionError())
def test_write_json__write_exception(mock_write_text):
    """Test irregular case, cant write text file"""

    # Given
    input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "report.json"
    input_vo = [1, 2, 3, 4, 5]
    expected_error = click.ClickException(f"Eze can't write file '{input_report_location}' or doesn't exist.")

    try:
        write_json(input_report_location, input_vo)
    except Exception as e:
        raised_error = e
    # Then
    assert str(expected_error) == str(raised_error)


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

    input = None
    expected_output = ""
    output = xescape(input)

    assert output == expected_output


def test_xescape__std():
    """Test normal case"""

    input = '\\" <evil-xml-tag/>'
    expected_output = "&#92;&quot; &lt;evil-xml-tag/&gt;"
    output = xescape(input)

    assert output == expected_output


def test_xescape__zero():
    """Test zero case"""

    input = 0
    expected_output = "0"
    output = xescape(input)

    assert output == expected_output
