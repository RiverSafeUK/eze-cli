# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,unused-argument

import urllib.error
from unittest import mock
from io import StringIO
import pytest

from eze.utils.io.http import request, request_json, spine_case_url
from eze.utils.error import EzeNetworkingError
from eze.utils.io.print import pretty_print_json


@mock.patch("urllib.request.urlopen")
def test_request_json__happy_path(mock_urlopen):
    # Given
    input_to_json = {"a": "b"}
    mock_urlopen.return_value = StringIO(pretty_print_json(input_to_json))
    # When
    output = request_json("https://someurl.com")
    # Then
    assert output == input_to_json


@mock.patch("urllib.request.urlopen")
def test_request_json__sad_path__bad_json(mock_urlopen):
    # Given
    expected_error = "Error in JSON response 'https://someurl.com', NOTJSON (Expecting value: line 1 column 1 (char 0))"
    mock_urlopen.return_value = StringIO("NOTJSON")
    # When
    with pytest.raises(EzeNetworkingError) as raised_error:
        request_json("https://someurl.com")
    # Then
    assert raised_error.value.message == expected_error


@mock.patch("urllib.request.urlopen")
def test_request__happy_path(mock_urlopen):
    # Given
    mock_urlopen.return_value = StringIO("helloworld")
    # When
    output = request("https://someurl.com")
    # Then
    assert output == "helloworld"


@mock.patch("urllib.request.urlopen")
def test_request__sad_path_bad_url(mock_urlopen):
    # Given
    expected_error = "Error accessing url 'https://someurl.com', Error: <urlopen error http://example.com>"
    mock_urlopen.side_effect = urllib.error.URLError("http://example.com")
    # When
    with pytest.raises(EzeNetworkingError) as raised_error:
        request("https://someurl.com")
    # Then
    assert raised_error.value.message == expected_error


@mock.patch("urllib.request.urlopen")
def test_request__sad_path(mock_urlopen):
    # Given
    expected_error = "Error accessing url 'https://someurl.com', Error: 500 (Internal Error [helloworld]"
    mocked_open_function = mock.mock_open(read_data=b"helloworld")
    mock_urlopen.side_effect = urllib.error.HTTPError(
        "http://example.com", 500, "Internal Error", {}, mocked_open_function()
    )
    # When
    with pytest.raises(EzeNetworkingError) as raised_error:
        request("https://someurl.com")
    # Then
    assert raised_error.value.message == expected_error


def test_spine_case_url__std_case_ssh():
    # Given
    expected_output = "RiverSafeUK-eze-cli"
    input = "git@github.com:RiverSafeUK/eze-cli.git"
    # When
    output = spine_case_url(input)
    # Then
    assert output == expected_output


def test_spine_case_url__std_case_http():
    # Given
    expected_output = "github-com-RiverSafeUK-eze-cli"
    input = "http://github.com/RiverSafeUK/eze-cli.git"
    # When
    output = spine_case_url(input)
    # Then
    assert output == expected_output


def test_spine_case_url__std_case_https():
    # Given
    expected_output = "github-com-RiverSafeUK-eze-cli"
    input = "https://github.com/RiverSafeUK/eze-cli.git"
    # When
    output = spine_case_url(input)
    # Then
    assert output == expected_output


def test_spine_case_url__std_case_https():
    # Given
    expected_output = "RiverSafeUK-eze-cli"
    input = "RiverSafeUK/eze-cli.git"
    # When
    output = spine_case_url(input)
    # Then
    assert output == expected_output
