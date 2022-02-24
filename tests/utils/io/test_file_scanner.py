import pytest

from eze.utils.io.file_scanner import delete_file_cache, populate_file_cache, find_files_by_name, find_files_by_path


def teardown_function(function):
    """Teardown function"""
    delete_file_cache()


mock_discovered_folders = ["src"]
mock_ignored_folders = ["node_modules"]
mock_discovered_files = ["Dockerfile", "src/thing.js"]
mock_discovered_filenames = ["Dockerfile", "thing.js"]
mock_discovered_types = {"Dockerfile": 1, ".js": 1}


def test_find_files_by_path__happy():
    # Given
    populate_file_cache(
        mock_discovered_folders,
        mock_ignored_folders,
        mock_discovered_files,
        mock_discovered_filenames,
        mock_discovered_types,
    )
    expected_output = ["src/thing.js"]
    test_output = find_files_by_path("src/.*")
    assert test_output == expected_output


def test_find_files_by_path__happy_but_empty():
    # Given
    populate_file_cache(
        mock_discovered_folders,
        mock_ignored_folders,
        mock_discovered_files,
        mock_discovered_filenames,
        mock_discovered_types,
    )
    expected_output = []
    test_output = find_files_by_path("does-not-exist")
    assert test_output == expected_output


def test_find_files_by_path__sad_invalid_regex():
    # Given
    populate_file_cache(
        mock_discovered_folders,
        mock_ignored_folders,
        mock_discovered_files,
        mock_discovered_filenames,
        mock_discovered_types,
    )
    with pytest.raises(Exception) as raised_error:
        test_output = find_files_by_path("*.py")
    assert raised_error.value.args[0] == "unable to parse regex '*.py' due to nothing to repeat"


def test_find_files_by_name__happy():
    # Given
    populate_file_cache(
        mock_discovered_folders,
        mock_ignored_folders,
        mock_discovered_files,
        mock_discovered_filenames,
        mock_discovered_types,
    )
    expected_output = ["src/thing.js"]
    test_output = find_files_by_name(".+[.]js")
    assert test_output == expected_output


def test_find_files_by_name__happy_but_empty():
    # Given
    populate_file_cache(
        mock_discovered_folders,
        mock_ignored_folders,
        mock_discovered_files,
        mock_discovered_filenames,
        mock_discovered_types,
    )
    expected_output = []
    test_output = find_files_by_name("does-not-exist")
    assert test_output == expected_output


def test_find_files_by_name__sad_invalid_regex():
    # Given
    populate_file_cache(
        mock_discovered_folders,
        mock_ignored_folders,
        mock_discovered_files,
        mock_discovered_filenames,
        mock_discovered_types,
    )
    with pytest.raises(Exception) as raised_error:
        test_output = find_files_by_name("*.py")
    assert raised_error.value.args[0] == "unable to parse regex '*.py' due to nothing to repeat"
