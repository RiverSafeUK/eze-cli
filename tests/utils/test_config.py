# pylint: disable=missing-module-docstring,missing-class-docstring

import copy

from eze.utils.config import (
    get_config_key,
    extract_embedded_run_type,
    get_config_keys,
    create_config_help,
    merge_configs,
    merge_from_root_base,
    merge_from_root_flat,
    merge_from_root_nested,
)
from eze.utils.io import create_tempfile_path
from tests.__fixtures__.fixture_helper import get_snapshot_directory


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


def test_get_config_keys__cast_str_as_list():
    # Given
    input_dict = {"SOME_KEY": "1234"}
    input_config = {"SOME_KEY": {"type": list}}
    expected_output = {"SOME_KEY": ["1234"]}
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
        "IGNORED_VULNERABILITIES": {
            "type": list,
            "help_text": """vulnerabilities to ignore, by CVE code or by name
feature only for use when vulnerability mitigated or on track to be fixed""",
        },
        "IGNORED_FILES": {
            "type": list,
            "help_text": """vulnerabilities in files or prefix folders to ignore
feature only for use when vulnerability mitigated or on track to be fixed""",
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


def test_merge_from_root_base__std():
    # Given
    expected_config = {"hello": "world"}
    input_dict = {"xxx-plugin": expected_config}
    input_plugin_name = "xxx-plugin"
    testee = {}
    # When
    merge_from_root_base(input_dict, testee, input_plugin_name)
    # Then
    assert testee == expected_config


def test_merge_from_root_flat__std():
    # Given
    expected_config = {"hello": "world"}
    input_dict = {"xxx-plugin": {}, "xxx-plugin_run1": expected_config}
    input_plugin_name = "xxx-plugin"
    input_run_type = "run1"
    testee = {}
    # When
    merge_from_root_flat(input_dict, testee, input_plugin_name, input_run_type)
    # Then
    assert testee == expected_config


def test_merge_from_root_nested__std():
    # Given
    expected_config = {"hello": "world"}
    input_dict = {"xxx-plugin": {"run1": expected_config}, "xxx-plugin_run1": {}}
    input_plugin_name = "xxx-plugin"
    input_run_type = "run1"
    testee = {}
    # When
    merge_from_root_nested(input_dict, testee, input_plugin_name, input_run_type)
    # Then
    assert testee == expected_config


def test_merge_configs__simple_merging():
    input_dict = {"hello": "world", "foo": {"bar": 1}}
    expected_config = copy.deepcopy(input_dict)
    testee = {}
    merge_configs(input_dict, testee)
    assert testee == expected_config


def test_merge_configs__simple_merging():
    input_dict = {"hello": "world", "foo": {"bar": 1}}
    expected_config = copy.deepcopy(input_dict)
    testee = {}
    merge_configs(input_dict, testee)
    assert testee == expected_config


def test_merge_configs__nested_deep_merging():
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
    testee = {}
    merge_configs(inital_dict, testee)
    # When
    merge_configs(input_dict, testee)
    # Then
    assert testee == expected_config
