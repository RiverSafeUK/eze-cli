# pylint: disable=missing-module-docstring,missing-class-docstring

from eze.core.language import LanguageRunnerMeta

from tests.__fixtures__.fixture_helper import get_snapshot_directory


class LanguageMetaTestBase:
    LanguageMetaClass = LanguageRunnerMeta
    SNAPSHOT_PREFIX = "language-meta"

    def test_help_text_fields(self, snapshot):
        # When
        short_description_output = self.LanguageMetaClass.short_description()
        install_output = self.LanguageMetaClass.install_help()
        more_info_output = self.LanguageMetaClass.more_info()
        # Then
        output = f"""short_description:
======================
{short_description_output}

install_help:
======================
{install_output}

more_info:
======================
{more_info_output}
"""
        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, f"plugins_languages/{self.SNAPSHOT_PREFIX}-help_text.txt")

    def test_install_help(self, snapshot):
        # When
        output = self.LanguageMetaClass.install_help()
        # Then
        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, f"plugins_languages/{self.SNAPSHOT_PREFIX}-install-help.txt")

    def assert_create_ezerc_snapshot_test(
        self,
        snapshot,
        input_config: dict = None,
        output_fixture_location: str = None,
    ):
        """Help function to take a input config, and test output matches given snapshot

        Default Output Snapshot:
            tests/plugins_tools/XXX-result-output.json"""
        # Given
        if not input_config:
            input_config = {"files": {}, "folders": {}}
        if not output_fixture_location:
            output_fixture_location = f"plugins_languages/{self.SNAPSHOT_PREFIX}-result-output.json"

        testee = self.LanguageMetaClass()
        testee.discovery.files = input_config["files"]
        testee.discovery.folders = input_config["folders"]
        # When
        output = testee.create_ezerc()
        output_snapshot = f"""{output["fragment"]}

========

{output["message"]}"""

        print(output_snapshot)
        # Then
        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output_snapshot, output_fixture_location)
