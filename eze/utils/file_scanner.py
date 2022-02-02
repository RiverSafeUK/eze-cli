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

IGNORED_FOLDERS: list = [
    # IDEs and Configs
    ".gradle",
    ".aws",
    ".idea",
    ".git",
    ".eze",
    ".coverage",
    "~",
    # TERRAFORM
    ".terraform",
    # NODE
    "node_modules",
    "build",
    "target",
    "vendor",
    # PYTHON
    ".pytest_cache",
    "__pycache__",
    ".env",
    ".venv",
    ".tox",
    "venv",
    "dist",
    "sdist"
]
IGNORED_FILES: list = [
    # IDEs and Configs
    # TERRAFORM
    ".terraform.lock.hcl",
    # NODE
    "package-lock.json",
    # PYTHON
]


def delete_file_cache() -> None:
    """delete file caching"""
    __c.ignored_folders = None
    __c.ignored_files = None
    __c.discovered_folders = None
    __c.discovered_files = None
    __c.discovered_filenames = None
    __c.discovered_types = None


def has_filetype(filetype: str) -> int:
    """will return count of given file type aka '.py'"""
    initialise_cache()
    if filetype not in __c.discovered_types:
        return 0
    return __c.discovered_types[filetype]


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
    initialise_cache()
    return __c.discovered_filenames


def get_file_list() -> list:
    """get list of filepaths aka backend\\function\\ezemcdbcrud\\src\\package.json"""
    initialise_cache()
    return __c.discovered_files


def get_ignored_folder_list() -> list:
    """get list of folders aka backend\\function\\ezemcdbcrud\\src\\"""
    initialise_cache()
    return __c.ignored_folders


def get_folder_list() -> list:
    """get list of folders aka backend\\function\\ezemcdbcrud\\src\\"""
    initialise_cache()
    return __c.discovered_folders

def initialise_cache ():
    """sets up cache of files for project"""
    if not __c.discovered_folders:
        [__c.discovered_folders, __c.ignored_folders, __c.discovered_files, __c.discovered_filenames,
         __c.discovered_types] = _build_file_list()

def _build_file_list(root_path: str = None) -> list:
    """build a list of folder and file names"""
    if not root_path:
        root_path = Path.cwd()
    walk_dir = os.path.abspath(root_path)

    root_prefix = len(str(Path(root_path))) + 1

    ignored_folders = []
    discovered_files = []
    discovered_folders = []
    discovered_filenames = []
    discovered_filetypes = {}

    for root, subdirs, files in os.walk(walk_dir):
        # Ignore Some directories
        for ignored_directory in IGNORED_FOLDERS:
            if ignored_directory in subdirs:
                ignored_folder_path = os.path.join(root, ignored_directory)[root_prefix:]
                ignored_folders.append(ignored_folder_path)
                subdirs.remove(ignored_directory)

        for subdir in subdirs:
            folder_path = os.path.join(root, subdir)[root_prefix:]
            discovered_folders.append(folder_path)

        for filename in files:
            file_path = os.path.join(root, filename)[root_prefix:]
            discovered_files.append(file_path)
            discovered_filenames.append(filename)
            filename_without_extension, extension = os.path.splitext(filename)
            if not extension:
                extension = filename_without_extension
            if extension not in discovered_filetypes:
                discovered_filetypes[extension] = 0
            discovered_filetypes[extension] += 1

    return [discovered_folders, ignored_folders, discovered_files, discovered_filenames, discovered_filetypes]
