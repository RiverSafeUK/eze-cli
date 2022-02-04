# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from eze.core.autoconfig import AutoConfigRunner


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
