# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from unittest import TestCase, mock

import pathlib
import tempfile

import pytest
from click import ClickException

from eze.core.config import EzeConfig
from eze.utils.config import merge_configs
from tests.__fixtures__.config.example_complex_ezerc import get_expected_full_config
from tests.__fixtures__.fixture_helper import get_path_fixture
from tests.__fixtures__.config import example_complex_dot_format_ezerc
from tests.__fixtures__.config import example_complex_ezerc


class TestEzeConfig(TestCase):
    @mock.patch("eze.core.config.EzeConfig.get_global_config_filename")
    @mock.patch("eze.core.config.EzeConfig.get_local_config_filename")
    def test_refresh_ezerc_config(self, mock_get_local_config_filename, mock_get_global_config_filename):
        # Given
        mock_get_local_config_filename.return_value = (
            pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "does-not-exist"
        )
        mock_get_global_config_filename.return_value = (
            pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "does-not-exist"
        )
        external_file = get_path_fixture("__fixtures__/config/example_complex_ezerc.toml")

        expected_output = get_expected_full_config()
        # When
        EzeConfig.refresh_ezerc_config(external_file)

        eze_config = EzeConfig.get_instance().config

        # Then
        assert eze_config == expected_output

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
        merge_configs(inital_dict, testee.config)
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
        merge_configs(inital_dict, testee.config)
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

    def test_get_plugin_config__base_run_case_2(self):
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
        with pytest.raises(ClickException) as raised_error:
            testee.get_scan_config()
        # Then
        assert raised_error.value.message == expected_error_message

    def test_get_plugin_config__real_toml_no_reporters_scan_type_plugin(self):
        # Given
        external_file = get_path_fixture("__fixtures__/config/example_broken_reporters_ezerc.toml")
        expected_error_message = (
            """The ./ezerc config missing scan.reporters list, run 'eze housekeeping create-local-config' to create"""
        )
        testee = EzeConfig([external_file])
        # When
        with pytest.raises(ClickException) as raised_error:
            testee.get_scan_config()
        # Then
        assert raised_error.value.message == expected_error_message
