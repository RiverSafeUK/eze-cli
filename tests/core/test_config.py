# pylint: disable=missing-module-docstring,missing-class-docstring

import copy
from unittest import TestCase

import pytest
from click import ClickException

from eze.core.config import EzeConfig, get_config_key, extract_embedded_run_type, get_config_keys, create_config_help
from eze.utils.io import create_tempfile_path
from tests.__fixtures__.config import example_complex_dot_format_ezerc
from tests.__fixtures__.config import example_complex_ezerc
from tests.__fixtures__.fixture_helper import get_path_fixture, get_snapshot_directory


def test_extract_embedded_run_type__no_change():
    input_plugin_name = "hello"
    input_run_type = "world"
    expected_output = ["hello", "world"]
    output = extract_embedded_run_type(input_plugin_name, input_run_type)
    assert output == expected_output


def test_extract_embedded_run_type__colon():
    input_plugin_name = "hello:world"
    input_run_type = None
    expected_output = ["hello", "world"]
    output = extract_embedded_run_type(input_plugin_name, input_run_type)
    assert output == expected_output


def test_extract_embedded_run_type__underscore():
    input_plugin_name = "hello_world"
    input_run_type = None
    expected_output = ["hello", "world"]
    output = extract_embedded_run_type(input_plugin_name, input_run_type)
    assert output == expected_output


def test_get_config_key__success():
    input_dict = {"hello": "world"}
    expected_output = "world"
    output = get_config_key(input_dict, "hello", str)
    assert output == expected_output


def test_get_config_key__wrong_type_default_case():
    input_dict = {"hello": 4}
    expected_output = "default_world"
    output = get_config_key(input_dict, "hello", str, "default_world")
    assert output == expected_output


def test_get_config_key__missing_default_case():
    input_dict = {}
    expected_output = "default_world"
    output = get_config_key(input_dict, "hello", str, "default_world")
    assert output == expected_output


def test_get_config_keys__std_case():
    # Given
    input_dict = {
        "SOME_KEY": "1234",
        "SOME_LIST": ["dog", "wolf"],
        "SOME_DICT": {"cat": "sofia"},
        "SOME_UNUSED_KEY": "FOO",
    }
    input_config = {
        "SOME_KEY": {"type": str},
        "SOME_LIST": {"type": list},
        "SOME_DICT": {"type": dict},
        "SOME_MISSING_KEY": {"type": str, "default": "DEFAULT IF MISSING"},
    }
    expected_output = {
        "SOME_DICT": {"cat": "sofia"},
        "SOME_KEY": "1234",
        "SOME_LIST": ["dog", "wolf"],
        "SOME_MISSING_KEY": "DEFAULT IF MISSING",
    }
    # When
    output = get_config_keys(input_dict, input_config)
    # Then
    assert output == expected_output


def test_create_config_help__real_case_snapshot(snapshot):
    # Given
    input_config = {
        "SOURCE": {
            "type": str,
            "default": ".",
            "help_text": """By default it is "." aka local folder
From grype help
Supports the following image sources:
    grype yourrepo/yourimage:tag     defaults to using images from a Docker daemon
    grype path/to/yourproject        a Docker tar, OCI tar, OCI directory, or generic filesystem directory

You can also explicitly specify the scheme to use:
    grype docker:yourrepo/yourimage:tag          explicitly use the Docker daemon
    grype docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
    grype oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Podman or otherwise)
    grype oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    grype dir:path/to/yourproject                read directly from a path on disk (any directory)
    grype sbom:path/to/syft.json                 read Syft JSON from path on disk
    grype registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)""",
        },
        "CONFIG_FILE": {
            "type": str,
            "help_text": """Grype config file location, by default Empty, maps to grype argument
  -c, --config string     application config file""",
        },
        "GRYPE_IGNORE_UNFIXED": {
            "type": bool,
            "default": False,
            "help_text": """if true ignores state = "not-fixed""" "",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-grype-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-grype-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
    }
    input_common_config: dict = {
        "ADDITIONAL_ARGUMENTS": {
            "type": str,
            "default": "",
            "help_text": """common field that can be used to postfix arbitrary arguments onto any plugin cli tooling""",
        },
        "IGNORE_BELOW_SEVERITY": {
            "type": str,
            "help_text": """vulnerabilities severities to ignore, by CVE severity level
aka if set to medium, would ignore medium/low/none/na
available levels: critical, high, medium, low, none, na""",
        },
        "IGNORED_VUNERABLITIES": {
            "type": list,
            "help_text": """vulnerabilities to ignore, by CVE code or by name
feature only for use when vunerablity mitigated or on track to be fixed""",
        },
        "IGNORED_FILES": {
            "type": list,
            "help_text": """vulnerabilities in files or prefix folders to ignore
feature only for use when vunerablity mitigated or on track to be fixed""",
        },
        "DEFAULT_SEVERITY": {
            "type": str,
            "help_text": """Severity to set vulnerabilities, when tool doesn't provide a severity, defaults to na
available levels: critical, high, medium, low, none, na""",
        },
    }
    # When
    output = create_config_help("anchore-grype", input_config, input_common_config)
    # Then
    # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
    snapshot.snapshot_dir = get_snapshot_directory()
    snapshot.assert_match(output, "core/config__create_config_help--real-case.txt")


def test_create_config_help__std_case_snapshot(snapshot):
    # Given
    input_config = {
        "SOME_KEY": {"type": str},
        "SOME_LIST": {"type": list},
        "SOME_DICT": {"type": dict},
        "SOME_MISSING_KEY": {"type": str, "default": "DEFAULT IF MISSING"},
        "HELP_TEST": {"type": str, "help_text": "some misc help text"},
        "HELP_EXAMPLE": {"type": str, "help_example": "some-value"},
        "HELP_EXAMPLE_BOOL": {"type": bool, "help_example": True},
        "HELP_EXAMPLE_LIST": {"type": list, "help_example": ["something"]},
    }
    # When
    output = create_config_help("mctool/jimmy-the-plugin", input_config)
    # Then
    # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
    snapshot.snapshot_dir = get_snapshot_directory()
    snapshot.assert_match(output, "core/config__create_config_help--std-case.txt")


class TestEzeConfig(TestCase):
    def test_creation__with_toml(self):
        # Given
        expected_output = {
            "black-duck": {"some_special_config_var": 0.1, "some_special_url": "https://somewhere important"},
            "notifiers": ["black-duck"],
            "scanners": ["black-duck"],
            "title": "Helloworld",
        }
        input_fixtures = [
            # to test if broken toml breaks parsing
            get_path_fixture("__fixtures__/config/example_broken_config.toml"),
            # contains above output
            get_path_fixture("__fixtures__/config/example_config.toml"),
        ]
        # When
        testee = EzeConfig(input_fixtures)
        # Then
        assert testee.config == expected_output

    def test_add_config__simple_merging(self):
        input_dict = {"hello": "world", "foo": {"bar": 1}}
        expected_config = copy.deepcopy(input_dict)
        testee = EzeConfig()
        testee._add_config(input_dict)
        assert testee.config == expected_config

    def test_add_config__nested_deep_merging(self):
        # Given
        inital_dict = {
            "hello": "world",
            "foo": {"bar": 1, "bar2": "should be same value"},
            "old_key": "do not touch me",
        }
        input_dict = {"hello": "updated world", "foo": {"bar": "new value"}, "new_key": "new key value"}
        expected_config = {
            "hello": "updated world",
            "foo": {"bar": "new value", "bar2": "should be same value"},
            "new_key": "new key value",
            "old_key": "do not touch me",
        }
        testee = EzeConfig()
        testee._add_config(inital_dict)
        # When
        testee._add_config(input_dict)
        # Then
        assert testee.config == expected_config

    def test_get_plugin_config__none(self):
        # Given
        inital_dict = {
            "hello": "world",
            "foo": {"bar": 1, "bar2": "should be same value"},
            "old_key": "do not touch me",
        }
        input_tool_name = "safety"
        expected_config = {}
        testee = EzeConfig()
        testee._add_config(inital_dict)
        # When
        output = testee.get_plugin_config(input_tool_name)
        # Then
        assert output == expected_config

    def test_get_plugin_config__simple(self):
        # Given
        inital_dict = {"safety": {"some": "key", "another": ["key"]}}
        input_tool_name = "safety"
        expected_config = {"some": "key", "another": ["key"]}
        testee = EzeConfig()
        testee._add_config(inital_dict)
        # When
        output = testee.get_plugin_config(input_tool_name)
        # Then
        assert output == expected_config

    def test_get_plugin_config__scan_case(self):
        # Given
        inital_dict = {
            "safety": {"some": "key", "another": ["key"]},
            "scan": {"dev": {"safety": {"some": "change"}}, "prod": {"safety": {"some": "not chosen change"}}},
        }
        input_tool_name = "safety"
        input_scan_type = "dev"
        expected_config = {"some": "change", "another": ["key"]}
        testee = EzeConfig([inital_dict])
        # When
        output = testee.get_plugin_config(input_tool_name, input_scan_type)
        # Then
        assert output == expected_config

    def test_get_plugin_config__base_run_case(self):
        # Given
        inital_dict = {
            "safety": {"some": "key", "another": ["key"]},
            "safety_special": {"some": "special-key", "another": ["very-key"]},
            "scan": {
                "dev": {"safety": {"some": "change", "some-thing": "from-dev"}},
                "prod": {"safety": {"some": "not chosen change"}},
            },
        }
        input_tool_name = "safety"
        input_scan_type = "dev"
        input_run_type = "special"
        expected_config = {"some": "special-key", "another": ["very-key"], "some-thing": "from-dev"}
        testee = EzeConfig([inital_dict])
        # When
        output = testee.get_plugin_config(input_tool_name, input_scan_type, input_run_type)
        # Then
        assert output == expected_config

    def test_get_plugin_config__base_run_case(self):
        # Given
        inital_dict = {
            "safety": {"some": "key", "another": ["key"]},
            "safety_special": {"some": "special-key", "another": ["very-key"]},
            "scan": {
                "dev": {
                    "safety": {"some": "change", "some-thing": "from-dev"},
                    "safety_special": {"some": "super-special-key", "another": ["very-super-special-thing"]},
                },
                "prod": {"safety": {"some": "not chosen change"}},
            },
        }
        input_tool_name = "safety"
        input_scan_type = "dev"
        input_run_type = "special"
        expected_config = {
            "some": "super-special-key",
            "another": ["very-super-special-thing"],
            "some-thing": "from-dev",
        }
        testee = EzeConfig([inital_dict])
        # When
        output = testee.get_plugin_config(input_tool_name, input_scan_type, input_run_type)
        # Then
        assert output == expected_config

    def test_get_plugin_config__language_run_case(self):
        # Given
        inital_dict = {
            "safety": {"some": "key", "another": ["key"]},
            "safety_special": {"some": "special-key", "another": ["very-key"]},
            "python": {
                "safety": {"some": "change", "some-thing": "from-python-dev"},
                "safety_special": {"some": "super-special-key", "another": ["very-super-special-thing"]},
            },
            "scan": {},
        }
        input_tool_name = "safety"
        input_scan_type = None
        input_run_type = "special"
        input_language = "python"
        expected_config = {
            "some": "super-special-key",
            "another": ["very-super-special-thing"],
            "some-thing": "from-python-dev",
        }
        testee = EzeConfig([inital_dict])
        # When
        output = testee.get_plugin_config(input_tool_name, input_scan_type, input_run_type, input_language)
        # Then
        assert output == expected_config

    def test_get_plugin_config__real_toml_complex_case(self):
        # Given
        external_file = get_path_fixture("__fixtures__/config/example_complex_ezerc.toml")

        expected_output = example_complex_ezerc.get_expected_full_config()
        # When
        testee = EzeConfig([external_file])
        eze_config = testee.config

        # Then
        assert eze_config == expected_output

    def test_get_plugin_config__real_toml_complex_case_simple_plugin(self):
        # Given
        external_file = get_path_fixture("__fixtures__/config/example_complex_ezerc.toml")

        expected_safety_output = example_complex_ezerc.get_expected_safety()
        # When
        testee = EzeConfig([external_file])
        eze_config = testee.config
        safety_config = testee.get_plugin_config("safety")

        # Then
        assert safety_config == expected_safety_output

    def test_get_plugin_config__real_toml_complex_case_run_type_plugin(self):
        # Given
        external_file = get_path_fixture("__fixtures__/config/example_complex_ezerc.toml")

        expected_safety_quick_output = example_complex_ezerc.get_expected_safety_quick()
        # When
        testee = EzeConfig([external_file])
        safety_quick_config = testee.get_plugin_config("safety:quick")
        safety_quick_config_via_underscore = testee.get_plugin_config("safety_quick")
        safety_quick_config_via_explicit_run_type = testee.get_plugin_config("safety", None, "quick")

        # Then
        assert safety_quick_config == expected_safety_quick_output
        assert safety_quick_config_via_underscore == expected_safety_quick_output
        assert safety_quick_config_via_explicit_run_type == expected_safety_quick_output

    def test_get_plugin_config__real_toml_complex_case_scan_type_plugin(self):
        # Given
        external_file = get_path_fixture("__fixtures__/config/example_complex_ezerc.toml")

        expected_safety_scan_output = example_complex_ezerc.get_expected_safety_slow()
        # When
        testee = EzeConfig([external_file])
        safety_scan_config = testee.get_plugin_config("safety:slow", "ci-prod")
        safety_scan_config_via_underscore = testee.get_plugin_config("safety_slow", "ci-prod")
        safety_scan_config_via_explicit_run_type = testee.get_plugin_config("safety", "ci-prod", "slow")

        # Then
        assert safety_scan_config == expected_safety_scan_output
        assert safety_scan_config_via_underscore == expected_safety_scan_output
        assert safety_scan_config_via_explicit_run_type == expected_safety_scan_output

    def test_get_plugin_config__real_toml_complex_case_dot_format_run_type_plugin(self):
        # Given
        external_file = get_path_fixture("__fixtures__/config/example_complex_dot_format_ezerc.toml")

        expected_safety_quick_output = example_complex_dot_format_ezerc.get_expected_safety_quick()
        # When
        testee = EzeConfig([external_file])
        safety_quick_config = testee.get_plugin_config("safety:quick")
        safety_quick_config_via_underscore = testee.get_plugin_config("safety_quick")
        safety_quick_config_via_explicit_run_type = testee.get_plugin_config("safety", None, "quick")

        # Then
        assert safety_quick_config == expected_safety_quick_output
        assert safety_quick_config_via_underscore == expected_safety_quick_output
        assert safety_quick_config_via_explicit_run_type == expected_safety_quick_output

    def test_get_plugin_config__real_toml_complex_case_dot_format_scan_type_plugin(self):
        # Given
        external_file = get_path_fixture("__fixtures__/config/example_complex_dot_format_ezerc.toml")

        expected_safety_scan_output = example_complex_dot_format_ezerc.get_expected_dot_safety_slow()
        # When
        testee = EzeConfig([external_file])
        safety_scan_config = testee.get_plugin_config("safety:slow", "ci-prod")
        safety_scan_config_via_underscore = testee.get_plugin_config("safety_slow", "ci-prod")
        safety_scan_config_via_explicit_run_type = testee.get_plugin_config("safety", "ci-prod", "slow")

        # Then
        assert safety_scan_config == expected_safety_scan_output
        assert safety_scan_config_via_underscore == expected_safety_scan_output
        assert safety_scan_config_via_explicit_run_type == expected_safety_scan_output

    def test_get_plugin_config__real_toml_no_tools_scan_type_plugin(self):
        # Given
        external_file = get_path_fixture("__fixtures__/config/example_broken_tools_ezerc.toml")
        expected_error_message = """The ./ezerc config missing required scan.tools/languages list, run 'eze housekeeping create-local-config' to create"""
        # When
        testee = EzeConfig([external_file])
        with pytest.raises(ClickException) as thrown_exception:
            testee.get_scan_config()
        # Then
        assert thrown_exception.value.message == expected_error_message

    def test_get_plugin_config__real_toml_no_reporters_scan_type_plugin(self):
        # Given
        external_file = get_path_fixture("__fixtures__/config/example_broken_reporters_ezerc.toml")
        expected_error_message = (
            """The ./ezerc config missing scan.reporters list, run 'eze housekeeping create-local-config' to create"""
        )
        testee = EzeConfig([external_file])
        # When
        with pytest.raises(ClickException) as thrown_exception:
            testee.get_scan_config()
        # Then
        assert thrown_exception.value.message == expected_error_message
