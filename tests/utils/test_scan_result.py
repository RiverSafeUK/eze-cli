# pylint: disable=missing-module-docstring,missing-class-docstring

from eze.utils.scan_result import (
    get_bom_license,
)


def test_get_bom_license__id_license():
    # Given
    input = {"license": {"id": "Apache"}}
    expected_output = "Apache"
    # When
    output = get_bom_license(input)
    # Then
    assert output == expected_output


def test_get_bom_license__id_license():
    # Given
    input = {"license": {"name": "Apache-via-name"}}
    expected_output = "Apache-via-name"
    # When
    output = get_bom_license(input)
    # Then
    assert output == expected_output


def test_get_bom_license__normalise_unknown():
    # Given
    input = {"license": {"name": "UNKNOWN"}}
    expected_output = "unknown"
    # When
    output = get_bom_license(input)
    # Then
    assert output == expected_output
