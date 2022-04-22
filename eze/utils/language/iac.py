"""helper functions for dealing with iac"""

from eze.utils.io.file_scanner import find_files_by_name


def get_dockerfile_projects() -> []:
    """give a list of docker projects"""
    docker_files: list = find_files_by_name("^Dockerfile$")
    return docker_files


def get_terraform_projects() -> []:
    """give a list of terraform projects"""
    terraform_files: list = find_files_by_name("^main.tf")
    return terraform_files
