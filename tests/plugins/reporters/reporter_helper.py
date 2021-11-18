# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from eze.core.reporter import ReporterMeta

from tests.__fixtures__.fixture_helper import get_snapshot_directory


class ReporterMetaTestBase:
    ReporterMetaClass = ReporterMeta
    SNAPSHOT_PREFIX = "reporter-meta"

    def test_help_text_fields(self, snapshot):
        # When
        short_description_output = self.ReporterMetaClass.short_description()
        config_output = self.ReporterMetaClass.config_help()
        install_output = self.ReporterMetaClass.install_help()
        license_output = self.ReporterMetaClass.license()
        more_info_output = self.ReporterMetaClass.more_info()
        # Then
        output = f"""short_description:
======================
{short_description_output}

config_help:
======================
{config_output}

install_help:
======================
{install_output}

license:
======================
{license_output}

more_info:
======================
{more_info_output}
"""
        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, f"plugins_reporters/{self.SNAPSHOT_PREFIX}-help_text.txt")

    def test_license__not_unknown(self):
        # Given
        unexpected_license = "Unknown"
        # When
        output = self.ReporterMetaClass.license()
        # Then
        assert output != unexpected_license

    def test_install_help(self, snapshot):
        # When
        output = self.ReporterMetaClass.install_help()
        # Then
        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, f"plugins_reporters/{self.SNAPSHOT_PREFIX}-install-help.txt")
