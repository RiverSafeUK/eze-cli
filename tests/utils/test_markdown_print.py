# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from eze.utils.markdown_print import scan_results_as_markdown
from tests.__fixtures__.fixture_helper import load_json_fixture, get_snapshot_directory
from eze.core.tool import ScanResult


def test_print_scan_results_as_markdown__empty(snapshot):
    # Given
    test_input = []

    # When
    output = scan_results_as_markdown(test_input)

    # Then
    # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
    snapshot.snapshot_dir = get_snapshot_directory()
    snapshot.assert_match(output, "utils/markdown__empty.md")


def test_print_scan_results_as_markdown(snapshot):
    # Given
    scan_results_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_scan_result.json")
    input_scan_results: list = [ScanResult(scan_result) for scan_result in scan_results_fixture]

    output = scan_results_as_markdown(input_scan_results)

    # Then
    # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
    snapshot.snapshot_dir = get_snapshot_directory()
    snapshot.assert_match(output, "utils/markdown__standard.md")
