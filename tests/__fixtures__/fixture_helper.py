"""Helper functions for loadding fixtures"""
import json
import os
from pathlib import Path
from unittest.mock import mock_open

from jsonschema import validate

from eze.utils.io.file import load_json, load_text


def get_path_fixture(path_from_tests: str) -> Path:
    """retrieves path to fixture"""
    file_dir = os.path.dirname(__file__)
    fixture_path = Path(file_dir) / ".." / path_from_tests
    return fixture_path


def get_snapshot_directory() -> Path:
    """retrieves path to snapshot directory"""
    return get_path_fixture("__snapshots__")


def load_json_fixture(path_from_tests: str):
    """
    load json fixture

    :raises EzeError
    """
    fixture_path = get_path_fixture(path_from_tests)
    json_dict = load_json(str(fixture_path))
    return json_dict


def load_text_fixture(path_from_tests: str):
    """
    load json fixture

    :raises EzeFileAccessError
    """
    fixture_path = get_path_fixture(path_from_tests)
    return load_text(str(fixture_path))


def assert_deep_equal(output, expected_output):
    """assert classes are deep equal using json conversion"""
    output_object = convert_to_std_object(output)
    expected_output_object = convert_to_std_object(expected_output)
    assert output_object == expected_output_object


def convert_to_std_object(input_object):
    """convert classes into standard vars"""
    return json.loads(json.dumps(input_object, default=vars))


def create_mocked_stream(path_from_tests):
    """setup mock open file/url steam"""
    mock_file = get_path_fixture(path_from_tests)
    with open(mock_file) as mock_stream:
        mock_data = mock_stream.read()

    return mock_open(read_data=mock_data)


def assert_valid_sarif(sarif: dict):
    """assert that a sarif file loaded in is valid

    Raises:

        `jsonschema.exceptions.ValidationError` if the instance
            is invalid

        `jsonschema.exceptions.SchemaError` if the schema itself
            is invalid
    """
    sarif_schema = load_json_fixture("__fixtures__/sarif/sarif-schema-2.1.0.json")
    validate(sarif, schema=sarif_schema)
