# pylint: disable=missing-module-docstring,missing-class-docstring
import os
import re

import pytest
from unittest import mock
from click.testing import CliRunner

from eze.cli.commands.test_remote_commands import test_remote_commands
from tests.__fixtures__.fixture_helper import get_snapshot_directory
from tests.__test_helpers__.mock_helper import setup_mock, teardown_mock


class TestRemoteCommand:
    def setup_method(module):
        """Clean up method"""
        setup_mock()

    def teardown_module(module):
        """teardown any state that was previously setup with a setup_module method."""
        teardown_mock()

    @mock.patch("eze.cli.utils.command_helpers.set_eze_config", mock.MagicMock(return_value=None))
    def test__test_remote_base(self, snapshot):
        """Test that the help message appears ok"""
        runner = CliRunner()
        result = runner.invoke(test_remote_commands, [])
        assert result.exit_code == 2
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_test_remote_commands/remote.txt")

    @mock.patch("eze.cli.utils.command_helpers.set_eze_config", mock.MagicMock(return_value=None))
    def test__test_remote_base_help(self, snapshot):
        """Test that the help message appears ok with explicit --help flag"""
        runner = CliRunner()
        result = runner.invoke(test_remote_commands, ["--help"])
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_test_remote_commands/remote_base_help.txt")

    def run_fake_scan(scan_type):
        print("scan run", end="")

    @pytest.mark.asyncio
    @mock.patch("eze.cli.commands.test_remote_commands.os.path.join", mock.MagicMock(return_value=os.getcwd()))
    @mock.patch("eze.cli.commands.test_remote_commands.git.Repo.clone_from", mock.MagicMock(return_value=None))
    @mock.patch("eze.cli.commands.test_remote_commands.EzeCore.run_scan", mock.AsyncMock(side_effect=run_fake_scan))
    @mock.patch("eze.cli.commands.test_remote_commands.set_eze_config", mock.MagicMock(return_value=None))
    @mock.patch("eze.cli.utils.command_helpers.set_eze_config", mock.MagicMock(return_value=None))
    def test_tool_run(self, snapshot):
        # Given
        # When
        runner = CliRunner()
        result = runner.invoke(test_remote_commands, ["--url", "https://google.com", "--branch", "main"])
        # Then
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_test_remote_commands/test_run_tool.txt")
        assert result.exit_code == 0
