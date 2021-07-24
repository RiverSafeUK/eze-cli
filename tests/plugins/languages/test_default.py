# pylint: disable=missing-module-docstring,missing-class-docstring

import os
import shutil
import tempfile

from eze.core.language import DefaultRunner
from tests.plugins.languages.language_helper import LanguageMetaTestBase


class TestDefaultRunner(LanguageMetaTestBase):
    LanguageMetaClass = DefaultRunner
    SNAPSHOT_PREFIX = "default"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)
        self.mock_pass_fail = ""

    def test_create_ezerc__snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_create_ezerc_snapshot_test(snapshot)

    def test_check_installed__success(self):
        # When
        expected_output = "inbuilt"
        output = self.LanguageMetaClass.check_installed()
        # Then
        assert output == expected_output
