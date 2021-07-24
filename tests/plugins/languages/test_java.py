# pylint: disable=missing-module-docstring,missing-class-docstring
import os
import shutil
import tempfile
from unittest import mock

from eze.plugins.languages.java import JavaRunner
from tests.plugins.languages.language_helper import LanguageMetaTestBase


class TestDefaultRunner(LanguageMetaTestBase):
    LanguageMetaClass = JavaRunner
    SNAPSHOT_PREFIX = "java"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)
        self.mock_pass_fail = ""

    def test_create_ezerc__snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_create_ezerc_snapshot_test(snapshot)

    @mock.patch("eze.plugins.languages.java.extract_cmd_version", mock.MagicMock(return_value="X.X.X"))
    def test_check_installed__success(self):
        # When
        expected_output = "inbuilt (java: X.X.X, mvn:X.X.X)"
        output = self.LanguageMetaClass.check_installed()
        # Then
        assert output == expected_output
