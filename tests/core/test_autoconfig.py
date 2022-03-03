# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import toml
from pytest import fail

from tests.__fixtures__.fixture_helper import get_snapshot_directory
from tests.__test_helpers__.mock_helper import unmock_file_scanner, mock_file_scanner
from eze.core.autoconfig import AutoConfigRunner


def teardown_function(function):
    unmock_file_scanner()


def test_AutoConfigRunner_create_tool_config_fragment__happy_case():
    # Given
    input_id = "semgrep"
    input_config = {
        "enabled_always": True,
        "enable_on_file": [],
        "enable_on_file_ext": [],
        "config": {"NO_ENTROPY": False, "INCLUDE_FULL_REASON": True},
    }
    expected_fragment = """[semgrep]
# Full List of Fields and Tool Help available "docker run riversafe/eze-cli tools help semgrep"
NO_ENTROPY = false
INCLUDE_FULL_REASON = true
"""
    # When
    fragment = AutoConfigRunner._create_tool_config_fragment(input_config, input_id)
    # Then
    assert fragment == expected_fragment


def test_create_ezerc_text__node_happy_case(snapshot):
    # Given
    mock_file_scanner()
    # When
    default_autoconfig_data: dict = AutoConfigRunner.get_autoconfig()
    output: str = AutoConfigRunner.create_ezerc_text(default_autoconfig_data)
    # Then
    snapshot.snapshot_dir = get_snapshot_directory()
    snapshot.assert_match(output, "core/autoconfig__node_auto_ezerc.yaml")
    try:
        return toml.loads(output)
    except toml.TomlDecodeError as error:
        fail(f"Failed parsing generated .ezerc, {error}")


def test_create_ezerc_text__java_happy_case(snapshot):
    # Given
    mock_file_scanner(
        mock_discovered_folders=["src/"],
        mock_ignored_folders=[],
        mock_discovered_files=["pom.xml", "src/app.java"],
        mock_discovered_filenames=["pom.xml", "app.java"],
        mock_discovered_types={".java"},
    )
    # When
    default_autoconfig_data: dict = AutoConfigRunner.get_autoconfig()
    output: str = AutoConfigRunner.create_ezerc_text(default_autoconfig_data)
    # Then
    snapshot.snapshot_dir = get_snapshot_directory()
    snapshot.assert_match(output, "core/autoconfig__java_auto_ezerc.yaml")
    try:
        return toml.loads(output)
    except toml.TomlDecodeError as error:
        fail(f"Failed parsing generated .ezerc, {error}")
