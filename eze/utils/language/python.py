"""helper functions for dealing with python"""

from eze.utils.io.file_scanner import find_files_by_name


def get_requirements_projects() -> []:
    """give a list of requirements_files"""
    requirements_files: list = find_files_by_name("^requirements.txt$")
    return requirements_files


def get_poetry_projects() -> []:
    """give a list of poetry projects"""
    poetry_files: list = find_files_by_name("^poetry.lock$")
    return poetry_files


def get_piplock_projects() -> []:
    """give a list of piplock projects"""
    piplock_files: list = find_files_by_name("^Pipfile.lock$")
    return piplock_files
