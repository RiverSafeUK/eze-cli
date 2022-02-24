# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from eze.utils.io.print import pretty_print_table, pretty_print_json
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


def test_pretty_print_json():
    """Test normal case, especially tests if can seralise classes"""

    class DummyClass:
        """Dummy Class"""

        def __init__(self):
            """constructor"""
            self.field1 = "should appear"
            self.field2 = "should appear"

        def func_should_not_appear(self):
            """dummy func"""
            return "foo"

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
