# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from eze.utils.print import pretty_print_table
from tests.__test_helpers__.mock_helper import unmock_print, mock_print


def test_pretty_print_table__empty():
    # Given
    mocked_print_output = mock_print()
    test_input = []
    expected_output = """Nothing to display
"""
    # When
    pretty_print_table(test_input)
    # Then
    unmock_print()
    output = mocked_print_output.getvalue()
    assert output == expected_output


def test_pretty_print_table__std_case():
    # Given
    mocked_print_output = mock_print()
    test_input = [
        {
            "Name": "Jimmy",
            "Age": "52",
        },
        {
            "Name": "Timmy",
            "Age": "7",
        },
        {
            "Name": "Emmy",
            "Age": "14",
        },
    ]
    expected_output = """| Name  | Age |
| ----- | --- |
| Jimmy | 52  |
| Timmy | 7   |
| Emmy  | 14  |
"""
    # When
    pretty_print_table(test_input)
    # Then
    unmock_print()
    output = mocked_print_output.getvalue()
    assert output == expected_output
