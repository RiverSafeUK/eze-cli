# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import TestCase

import eze.utils.windowslex as windowslex


class TestWindowslex(TestCase):
    def test_join__with_at(self):
        # Given
        expected_output = 'trufflehog3 -json "mel@a$£" --exclude "reports/bandit_informal-python-report.json$"'
        input = [
            "trufflehog3",
            "-json",
            "mel@a$£",
            "--exclude",
            "reports/bandit_informal-python-report.json$",
        ]
        # When
        output = windowslex.join(input)
        # Then
        assert output == expected_output

    def test_join__with_slash(self):
        # Given
        expected_output = (
            'trufflehog3 -o reports/truffleHog-python-report.json --exclude ".*\\(node_modules|build?|.DS_Store)$"'
        )
        input = [
            "trufflehog3",
            "-o",
            "reports/truffleHog-python-report.json",
            "--exclude",
            ".*\\(node_modules|build?|.DS_Store)$",
        ]
        # When
        output = windowslex.join(input)
        # Then
        assert output == expected_output

    def test_join__with_spaces(self):
        # Given
        expected_output = 'some-command --something "PATH-TO-EXCLUDED-FOLDER/.*" "some thing with spaces"'
        input = ["some-command", "--something", "PATH-TO-EXCLUDED-FOLDER/.*", "some thing with spaces"]
        # When
        output = windowslex.join(input)
        # Then
        assert output == expected_output

    def test_quote__no_change(self):
        # Given
        expected_output = "--json"
        input = "--json"
        # When
        output = windowslex.quote(input)
        print(output)
        # Then
        assert output == expected_output

    def test_quote__special_characters(self):
        # Given
        expected_output = '"reports\\bandit_informal-python-report.json"'
        input = "reports\\bandit_informal-python-report.json"
        # When
        output = windowslex.quote(input)
        print(output)
        # Then
        assert output == expected_output

    def test_quote__spaces(self):
        # Given
        expected_output = '"C:\\dev\\folder with spaces\\some-bin.exe"'
        input = "C:\\dev\\folder with spaces\\some-bin.exe"
        # When
        output = windowslex.quote(input)
        print(output)
        # Then
        assert output == expected_output
