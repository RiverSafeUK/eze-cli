# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import pytest

from eze.utils.io.print import (
    pretty_print_table,
    pretty_print_json,
    truncate,
    generate_markdown_list,
    generate_markdown_header,
)
from tests.__test_helpers__.mock_helper import unmock_print, mock_print


def generate_header__std_case():
    # Given
    test_input = " hello world"
    expected_output = """
# hello world"""
    # When
    output = generate_markdown_header(test_input)
    # Then
    assert output == expected_output


def generate_header__level_2_std_case():
    # Given
    test_input = " hello world"
    expected_output = """
## hello world"""
    # When
    output = generate_markdown_header(test_input, 2)
    # Then
    assert output == expected_output


def test_generate_markdown_list__std_case():
    # Given
    test_input = ["hello ", " line", " world "]
    expected_output = """* hello
* line
* world"""
    # When
    output = generate_markdown_list(test_input)
    # Then
    assert output == expected_output


def test_generate_markdown_list__std_multiline_case():
    # Given
    test_input = [
        "hello ",
        """ line1
    line2
line3""",
        " world ",
    ]
    expected_output = """* hello
* line1
  line2
  line3
* world"""
    # When
    output = generate_markdown_list(test_input)
    # Then
    assert output == expected_output


def test_generate_markdown_list__std_multiline_with_empty_case():
    # Given
    test_input = [
        "hello ",
        """ line1

    line2
    

line3""",
        " world ",
    ]
    expected_output = """* hello
* line1
  line2
  line3
* world"""
    # When
    output = generate_markdown_list(test_input)
    # Then
    assert output == expected_output


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


truncate_test_data = [
    ("short string test", "short text", "short text"),
    ("empty string test", "", ""),
    ("multiline string test", "line 1\nline 2\nline 3", "line 1"),
    (
        "long string test",
        """Provides an older in-memory Extensible Markup Language (XML) programming interface that enables you to modify XML documents. Developers should prefer the classes in the System.Xml.XDocument package.

Commonly Used Types:
System.Xml.XmlNode
System.Xml.XmlElement
System.Xml.XmlAttribute
System.Xml.XmlDocument
System.Xml.XmlDeclaration
System.Xml.XmlText
System.Xml.XmlComment
System.Xml.XmlNodeList
System.Xml.XmlWhitespace
System.Xml.XmlCDataSection""",
        "Provides an older in-memory Extensible Markup Language (XML) programming interf…",
    ),
]


@pytest.mark.parametrize("title,input_str,expected_output", truncate_test_data)
def test_truncate(title, input_str, expected_output):
    output = truncate(input_str)
    assert output == expected_output
