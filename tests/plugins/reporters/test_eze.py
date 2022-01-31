# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import shutil
import tempfile
from unittest import mock
from unittest.mock import patch

import pytest
from git import InvalidGitRepositoryError
from eze.plugins.reporters.eze import EzeReporter
from eze.utils.error import EzeConfigError
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase


class MockGitBranch:
    def __init__(self):
        self.name = "feature/helloworld"


class MockSuccessGitRepo:
    def __init__(self):
        self.active_branch = MockGitBranch()


class MockUnsuccessGitRepo:
    def __getattribute__(self, key):
        if key == "active_branch":
            raise InvalidGitRepositoryError("No git repo error")


class TestEzeReporter(ReporterMetaTestBase):
    ReporterMetaClass = EzeReporter
    SNAPSHOT_PREFIX = "eze"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)

    def test_check_installed_sanity(self):
        # When
        output = EzeReporter.check_installed()
        # Then
        assert isinstance(output, str)
        assert len(output) > 0

    @mock.patch.dict(
        os.environ,
        {
            "BUILD_SOURCEBRANCH": "",
            "SYSTEM_PULLREQUEST_SOURCEBRANCH": "",
            "BUILD_SOURCEBRANCHNAME": "",
            "AWS_BRANCH": "",
        },
    )
    @patch("git.Repo")
    def test_creation__no_config_git_info_missing(self, mock_repo):
        # Given
        expected_error_message = (
            "requires branch supplied via 'CODEBRANCH_NAME' config field or a checked out git repo in current dir"
        )
        mock_repo.return_value = MockUnsuccessGitRepo()
        input_config = {
            "APIKEY": "MOCK_APIKEY",
            "CONSOLE_ENDPOINT": "MOCK_CONSOLE_ENDPOINT",
            "CODEBASE_ID": "MOCK_CODEBASE_ID",
        }
        # When
        with pytest.raises(EzeConfigError) as raised_error:
            EzeReporter(input_config)
        # Then
        assert raised_error.value.message == expected_error_message

    @mock.patch.dict(os.environ, {"BUILD_SOURCEBRANCHNAME": "", "AWS_BRANCH": ""})
    @patch("git.Repo")
    def test_creation__no_config_CONSOLE_ENDPOINT_missing(self, mock_repo):
        # Given
        expected_error_message = """required param 'CONSOLE_ENDPOINT' missing from configuration
Management console url as specified by eze management console /profile page
it can also be specified as the environment variable EZE_CONSOLE_ENDPOINT
get EZE_CONSOLE_ENDPOINT from eze management console profile page"""
        # Given valid inside valid git repo
        mock_repo.return_value = MockSuccessGitRepo()
        input_config = {
            "CONSOLE_ENDPOINT": "",
            "CODEBASE_ID": "MOCK_CODEBASE_ID",
            "CODEBRANCH_NAME": "MOCK_CODEBRANCH_NAME",
            "APIKEY": "CONSOLE_ENDPOINT",
        }
        # When
        with pytest.raises(EzeConfigError) as raised_error:
            EzeReporter(input_config)
        # Then
        assert raised_error.value.message == expected_error_message

    def test_creation__simple_config_parsing(self):
        # Given
        input_config = {
            "APIKEY": "MOCK_APIKEY",
            "CONSOLE_ENDPOINT": "MOCK_CONSOLE_ENDPOINT",
            "CODEBASE_ID": "MOCK_CODEBASE_ID",
            "CODEBRANCH_NAME": "MOCK_CODEBRANCH_NAME",
        }
        expected_config = {
            "APIKEY": "MOCK_APIKEY",
            "CONSOLE_ENDPOINT": "MOCK_CONSOLE_ENDPOINT",
            "CODEBASE_ID": "MOCK_CODEBASE_ID",
            "CODEBRANCH_NAME": "MOCK_CODEBRANCH_NAME",
        }
        # When
        testee = EzeReporter(input_config)
        # Then
        assert testee.config == expected_config

    @pytest.mark.skip(reason="Mocking of http endpoint not implemented")
    async def test_run_report_snapshot(self, monkeypatch, snapshot):
        """Test that given fixture scan output matches expectations"""
