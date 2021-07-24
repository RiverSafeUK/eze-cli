# pylint: disable=missing-module-docstring,missing-class-docstring
import os
import shutil
import tempfile
from unittest import mock

from eze.plugins.languages.python import PythonRunner
from tests.plugins.languages.language_helper import LanguageMetaTestBase


class TestDefaultRunner(LanguageMetaTestBase):
    LanguageMetaClass = PythonRunner
    SNAPSHOT_PREFIX = "python"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)
        self.mock_pass_fail = ""

    def test_create_ezerc__snapshot(self, snapshot):
        # Test container fixture and snapshot
        config = {"files": {"REQUIREMENTS": ["requirements.txt"]}, "folders": {}}
        self.assert_create_ezerc_snapshot_test(snapshot, config)

    @mock.patch("eze.plugins.languages.python.extract_cmd_version", mock.MagicMock(return_value="X.X.X"))
    def test_check_installed__success(self):
        # When
        expected_output = "inbuilt (python: X.X.X, pip:X.X.X)"
        output = self.LanguageMetaClass.check_installed()
        # Then
        assert output == expected_output
