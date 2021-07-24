# pylint: disable=missing-module-docstring,missing-class-docstring

import pathlib
import tempfile
from unittest import mock

from eze.cli.utils import config
from eze.core.config import EzeConfig
from tests.__fixtures__.config.example_complex_ezerc import get_expected_full_config
from tests.__fixtures__.fixture_helper import get_path_fixture


@mock.patch("eze.cli.utils.config.get_global_config_filename")
@mock.patch("eze.cli.utils.config.get_local_config_filename")
def test_set_eze_config(mock_get_local_config_filename, mock_get_global_config_filename):
    # Given
    mock_get_local_config_filename.return_value = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "does-not-exist"
    mock_get_global_config_filename.return_value = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "does-not-exist"
    external_file = get_path_fixture("__fixtures__/config/example_complex_ezerc.toml")

    expected_output = get_expected_full_config()
    # When
    output = config.set_eze_config(external_file)

    eze_config = EzeConfig.get_instance().config

    # Then
    assert eze_config == expected_output
