# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import pytest

from jsonschema.exceptions import ValidationError
from tests.__fixtures__.fixture_helper import (
    load_json_fixture,
    assert_deep_equal,
    get_snapshot_directory,
    assert_valid_sarif,
)


class MutableExampleClass:
    """Dummy Class"""

    def __init__(self, mutable_test: dict = {}):
        # WARNING: mutable_test test parameter deliberating mutable
        self.mutable_config = mutable_test


def test_load_json_fixture():
    """Test that json fixture can be loaded"""

    sample_json_path = "__fixtures__/io/sample_json.json"
    expected_output = {"Iam": "json", "someArray": [], "someInt": 1, "someNull": None, "someObject": {}}
    output = load_json_fixture(sample_json_path)

    assert output == expected_output


def test_assert_deep_equal():
    """Test that classes can be compared deeply"""

    output = MutableExampleClass({"hello": "world"})
    expected_output = MutableExampleClass({"hello": "world"})

    assert_deep_equal(output, expected_output)


def test_python_sanity_class_default_mutablity():
    """Example of why to not set dicts and lists as raw defaults, at somepoint python might make this sane"""

    testee1 = MutableExampleClass()
    testee2 = MutableExampleClass()
    testee1.mutable_config["hello"] = "testee2"

    assert testee2.mutable_config["hello"] == "testee2"


def test_python_snapshot_sanity_case(snapshot):
    """Example of the snapshot working"""

    snapshot.snapshot_dir = get_snapshot_directory()
    snapshot.assert_match("helloworld", "helloworld.txt")


def test_assert_valid_sarif_sanity_success_case():
    """Example of the sarif working"""
    example_sarif = load_json_fixture("__fixtures__/sarif/valid-microsoft-reference.sarif")
    assert_valid_sarif(example_sarif)
    assert "did not raise exception" == "did not raise exception"


def test_assert_valid_sarif_sanity_failure_case():
    """Example of the sarif not working"""

    example_sarif = load_json_fixture("__fixtures__/sarif/broken-example.sarif")
    expected_error_message = "Additional properties are not allowed ('schema' was unexpected)"

    with pytest.raises(ValidationError) as thrown_exception:
        assert_valid_sarif(example_sarif)
    # Then
    assert thrown_exception.value.message == expected_error_message
