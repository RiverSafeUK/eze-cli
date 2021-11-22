# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,unused-argument

import urllib.error
from unittest import mock
from io import StringIO
import pytest

from eze.utils.http import request, request_json
from eze.utils.error import EzeNetworkingError
from eze.utils.io import pretty_print_json


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
    with pytest.raises(EzeNetworkingError) as captured_exception:
        request_json("https://someurl.com")
    # Then
    assert captured_exception.value.message == expected_error


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
    with pytest.raises(EzeNetworkingError) as captured_exception:
        request("https://someurl.com")
    # Then
    assert captured_exception.value.message == expected_error


@mock.patch("urllib.request.urlopen")
def test_request__sad_path(mock_urlopen):
    # Given
    expected_error = "Error accessing url 'https://someurl.com', Error: 500 (Internal Error [helloworld]"
    mocked_open_function = mock.mock_open(read_data=b"helloworld")
    mock_urlopen.side_effect = urllib.error.HTTPError(
        "http://example.com", 500, "Internal Error", {}, mocked_open_function()
    )
    # When
    with pytest.raises(EzeNetworkingError) as captured_exception:
        request("https://someurl.com")
    # Then
    assert captured_exception.value.message == expected_error
