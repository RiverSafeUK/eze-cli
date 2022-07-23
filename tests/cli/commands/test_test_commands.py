# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import os
import pytest
from unittest import mock
from click.testing import CliRunner
from eze.cli.commands.test_commands import (
    run_eze_scan_on_git_remote_repo,
    call_remote_scan_endpoint,
    test_command as normal_test_command,
)
from tests.__fixtures__.fixture_helper import get_snapshot_directory
from tests.__test_helpers__.mock_helper import setup_mock, teardown_mock


class TestTestCommands:
    def setup_method(self):
        """Clean up method"""
        setup_mock()

    def teardown_module(self):
        """teardown any state that was previously setup with a setup_module method."""
        teardown_mock()

    @mock.patch("eze.cli.commands.test_commands.EzeConfig.refresh_ezerc_config", mock.MagicMock(return_value=None))
    def test__test_base_help(self, snapshot):
        """Test that the help message appears ok with explicit --help flag"""
        runner = CliRunner()
        result = runner.invoke(normal_test_command, ["--help"])
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_test_commands/normal_base_help.txt")

    @mock.patch("eze.cli.commands.test_commands.EzeConfig.refresh_ezerc_config", mock.MagicMock(return_value=None))
    def test__call_remote_scan_endpoint_help(self, snapshot):
        """Test that the help message appears ok with explicit --help flag"""
        runner = CliRunner()
        result = runner.invoke(call_remote_scan_endpoint, ["--help"])
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_test_commands/online_base_help.txt")

    @mock.patch("eze.cli.commands.test_commands.EzeConfig.refresh_ezerc_config", mock.MagicMock(return_value=None))
    def test__run_eze_scan_on_git_remote_repo_help(self, snapshot):
        """Test that the help message appears ok with explicit --help flag"""
        runner = CliRunner()
        result = runner.invoke(run_eze_scan_on_git_remote_repo, ["--help"])
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_test_commands/remote_base_help.txt")

    @mock.patch("eze.cli.commands.test_commands.EzeConfig.refresh_ezerc_config", mock.MagicMock(return_value=None))
    def test__run_eze_scan_on_git_remote_repo_base(self, snapshot):
        """Test that the help message appears ok"""
        runner = CliRunner()
        result = runner.invoke(run_eze_scan_on_git_remote_repo, [])
        assert result.exit_code == 2
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_test_commands/remote.txt")

    def run_fake_scan(self, reporters):
        print("scan run", end="")

    @pytest.mark.asyncio
    @mock.patch("eze.cli.commands.test_commands.os.path.join", mock.MagicMock(return_value=os.getcwd()))
    @mock.patch("eze.cli.commands.test_commands.git.Repo.clone_from", mock.MagicMock(return_value=None))
    @mock.patch("eze.cli.commands.test_commands.EzeCore.run_scan", mock.AsyncMock(side_effect=run_fake_scan))
    @mock.patch("eze.cli.commands.test_commands.EzeCore.auto_build_ezerc", mock.AsyncMock(return_value=None))
    @mock.patch("eze.cli.commands.test_commands.EzeConfig.refresh_ezerc_config", mock.MagicMock(return_value=None))
    def test_tool_run__with_no_rebuild(self, snapshot):
        # Given
        # When
        runner = CliRunner()
        result = runner.invoke(run_eze_scan_on_git_remote_repo, ["--url", "https://google.com", "--branch", "main"])
        # Then
        assert result.exception is None
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_test_commands/test_run_tool.txt")
        assert result.exit_code == 0
