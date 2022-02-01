"""Basic file finder utility
"""
import os
import re
from pathlib import Path


class Cache:
    """Cache class container"""


__c = Cache()
__c.discovered_files = None
__c.discovered_folders = None

IGNORE_FOLDERS = [
    ".git",
    ".idea",
    "node_modules",
    ".gradle",
    "venv",
    "~",
    "__pycache__",
    ".pytest_cache",
    "target",
]


def delete_file_cache() -> None:
    """delete file caching"""
    __c.discovered_folders = None
    __c.discovered_files = None
    __c.discovered_filenames = None


def find_files_by_path(regex_str: str) -> list:
    """find list of matching files by full path aka 'backend\\function\\ezemcdbcrud\\src\\package.json'"""
    list_of_files: list = get_file_list()
    regex = re.compile(regex_str)
    return list(filter(regex.match, list_of_files))


def find_files_by_name(regex_str: str) -> list:
    """find list of matching files by name aka 'package.json'"""
    list_of_files: list = get_file_list()
    list_of_filenames: list = get_filename_list()
    regex = re.compile(regex_str)
    counter = 0
    files_by_name = []
    for filename in list_of_filenames:
        if regex.match(filename):
            files_by_name.append(list_of_files[counter])
        counter += 1
    return files_by_name


def get_filename_list() -> list:
    """get list of files aka package.json"""
    if not __c.discovered_files:
        [__c.discovered_folders, __c.discovered_files, __c.discovered_filenames] = _build_file_list()
    return __c.discovered_filenames


def get_file_list() -> list:
    """get list of filepaths aka backend\\function\\ezemcdbcrud\\src\\package.json"""
    if not __c.discovered_files:
        [__c.discovered_folders, __c.discovered_files, __c.discovered_filenames] = _build_file_list()
    return __c.discovered_files


def get_folder_list() -> list:
    """get list of folders aka backend\\function\\ezemcdbcrud\\src\\"""
    if not __c.discovered_folders:
        [__c.discovered_folders, __c.discovered_files] = _build_file_list()
    return __c.discovered_folders


def _build_file_list(root_path: str = None) -> list:
    """build a list of folder and file names"""
    if not root_path:
        root_path = Path.cwd()
    walk_dir = os.path.abspath(root_path)

    root_prefix = len(str(Path(root_path))) + 1

    discovered_files = []
    discovered_folders = []
    discovered_filenames = []

    for root, subdirs, files in os.walk(walk_dir):
        # Ignore Some directories
        for ignored_directory in IGNORE_FOLDERS:
            if ignored_directory in subdirs:
                subdirs.remove(ignored_directory)

        for subdir in subdirs:
            folder_path = os.path.join(root, subdir)[root_prefix:]
            discovered_folders.append(folder_path)

        for filename in files:
            file_path = os.path.join(root, filename)[root_prefix:]
            discovered_files.append(file_path)
            discovered_filenames.append(filename)

    return [discovered_folders, discovered_files, discovered_filenames]
