# pylint: disable=missing-module-docstring,missing-class-docstring

import os
import pathlib
import shutil
import tempfile
from unittest import mock

from click.testing import CliRunner

from eze.cli.commands.housekeeping_commands import (
    housekeeping_group,
    create_global_config_command,
    list_locations_command,
)
from tests.__fixtures__.fixture_helper import get_snapshot_directory
from tests.__test_helpers__.mock_helper import setup_mock as mock_setup, teardown_mock

EXPECTED_HOUSEKEEPING_HELP = """Usage: housekeeping [OPTIONS] COMMAND [ARGS]...

  container for miscellaneous house keeping commands

Options:
  --help  Show this message and exit.

Commands:
  create-global-config  create global config file
  create-local-config   create local config file
"""


class TestHousekeepingCommand:
    def setup_method(module):
        """Clean up method"""
        mock_setup()
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)

    def teardown_module(module):
        """teardown any state that was previously setup with a setup_module method."""
        teardown_mock()

    def test_housekeeping_base_help(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(housekeeping_group, ["--help"])
        assert result.exit_code == 0
        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_housekeeping_commands/housekeeping_base_help.txt")

    @mock.patch("eze.cli.commands.housekeeping_commands.EzeConfig.get_global_config_filename")
    @mock.patch("eze.cli.commands.housekeeping_commands.EzeConfig.get_local_config_filename")
    def test_create_global_config_command(self, mock_get_local_config_filename, mock_get_global_config_filename):
        tmp_local_file = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-local-testfile"
        mock_get_local_config_filename.return_value = tmp_local_file
        tmp_global_file = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-global-testfile"
        mock_get_global_config_filename.return_value = tmp_global_file

        expected_success_message = f"Successfully written configuration file to '{tmp_global_file}'"
        runner = CliRunner()
        result = runner.invoke(create_global_config_command, [])
        assert result.output.strip() == expected_success_message
        assert result.exit_code == 0

    @mock.patch("eze.cli.commands.housekeeping_commands.EzeConfig.get_global_config_filename")
    @mock.patch("eze.cli.commands.housekeeping_commands.EzeConfig.get_local_config_filename")
    def test_create_global_config_command__already_exists_case(
        self, mock_get_local_config_filename, mock_get_global_config_filename
    ):
        tmp_local_file = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-local-testfile"
        mock_get_local_config_filename.return_value = tmp_local_file
        tmp_global_file = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-global-testfile"
        mock_get_global_config_filename.return_value = tmp_global_file

        expected_failure_message = f"unable to create config '{tmp_global_file}' as it already exists"
        runner = CliRunner()
        # Create file
        runner.invoke(create_global_config_command, [])
        # Then attempt to create file
        result = runner.invoke(create_global_config_command, [])
        assert result.output.strip() == expected_failure_message
        assert result.exit_code == 0

    @mock.patch("eze.cli.commands.housekeeping_commands.EzeConfig.get_global_config_filename")
    @mock.patch("eze.cli.commands.housekeeping_commands.EzeConfig.get_local_config_filename")
    def test_list_locations_command(self, mock_get_local_config_filename, mock_get_global_config_filename):
        tmp_local_file = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-local-testfile"
        mock_get_local_config_filename.return_value = tmp_local_file
        tmp_global_file = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-global-testfile"
        mock_get_global_config_filename.return_value = tmp_global_file

        expected_success_message = f"""Global configuration file: '{tmp_global_file}'
Local configuration file: '{tmp_local_file}'"""
        runner = CliRunner()
        result = runner.invoke(list_locations_command, [])
        assert result.output.strip() == expected_success_message
        assert result.exit_code == 0

    def test_documentation_list(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(housekeeping_group, ["documentation"])
        assert result.exit_code == 0
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_housekeeping_commands/documentation_list.txt")
