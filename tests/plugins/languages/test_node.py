# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import os
import shutil
import tempfile
from unittest import mock

from eze.plugins.languages.node import NodeRunner
from tests.plugins.languages.language_helper import LanguageMetaTestBase


class TestDefaultRunner(LanguageMetaTestBase):
    LanguageMetaClass = NodeRunner
    SNAPSHOT_PREFIX = "node"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)
        self.mock_pass_fail = ""

    def test_create_ezerc__snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_create_ezerc_snapshot_test(snapshot)

    @mock.patch("eze.plugins.languages.node.extract_cmd_version", mock.MagicMock(return_value="X.X.X"))
    def test_check_installed__success(self):
        # When
        expected_output = "inbuilt (node: X.X.X, npm:X.X.X)"
        output = self.LanguageMetaClass.check_installed()
        # Then
        assert output == expected_output
