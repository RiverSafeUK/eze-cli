"""Basic cli helpers utils

handles detecting versions of tools
"""
import re

from eze.utils.cli.run import run_cmd, cmd_exists, has_missing_exe_output
from eze.utils.semvar import is_semvar


def extract_cmd_version(command: list, ignored_errors_list: list = None) -> str:
    """
    Run cmd and extract version number from output
    """
    completed_process = run_cmd(command, False)
    output = completed_process.stdout
    error_output = completed_process.stderr
    if has_missing_exe_output(output):
        return ""
    version = _extract_version(output)
    is_acceptable_stderr = not error_output or _contains_list_element(error_output, ignored_errors_list)
    is_valid_version = is_semvar(version) or version != output
    if not is_valid_version or not is_acceptable_stderr:
        version = ""
    return version


def extract_version_from_maven(mvn_package: str) -> str:
    """
    Check maven package metadata and checks for Maven version
    """
    ignored_errors_list = ["WARNING: An illegal reflective access operation has occurred"]
    command: list = ["mvn", "-B", f"-Dplugin={mvn_package}", "help:describe"]
    completed_process = run_cmd(command, False)
    output = completed_process.stdout
    error_output = completed_process.stderr
    if has_missing_exe_output(output):
        return ""
    version = _extract_maven_version(output)
    is_acceptable_stderr = not error_output or _contains_list_element(error_output, ignored_errors_list)
    if not version or not is_acceptable_stderr:
        version = ""
    return version


def detect_pip_executable_version(pip_package: str, cli_command: str) -> str:
    """Check pip package metadata and check for pip version"""
    # 1. detect tool on command line
    # 2. detect version via pip
    #
    # 1. detect if tool on command line
    executable_path = cmd_exists(cli_command)
    if not executable_path:
        return ""
    # 2. detect version via pip, to see what version is installed on cli
    version = _extract_version_from_pip(pip_package)
    if not version:
        return "Non-Pip version Installed"
    return version


def _extract_version(value: str) -> str:
    """Take output and check for common version patterns"""
    version_matcher = re.compile("[0-9]+[.]([0-9]+[.]?:?)+")
    version_str = re.search(version_matcher, value)
    if version_str:
        return value[version_str.start() : version_str.end()]
    return value


def _contains_list_element(text: str, element_list: list = None) -> bool:
    """checks if given text contains list element"""
    if not element_list:
        return False
    for element in element_list:
        if element in text:
            return True
    return False


def _extract_maven_version(value: str) -> str:
    """Take Maven output and checks for version patterns"""
    leading_number_regex = re.compile("Version: ([0-9].[0-9](.[0-9])?)")
    leading_number = re.search(leading_number_regex, value)
    if leading_number is None:
        return ""
    return leading_number.group(1)


def _extract_version_from_pip(pip_package: str) -> str:
    """Run pip for package and check for common version patterns"""
    pip_command = _detect_pip_command()
    return extract_cmd_version([pip_command, "show", pip_package])


def _detect_pip_command() -> str:
    """Run pip3 and pip to detect which is installed"""
    version = extract_cmd_version(["pip3", "--version"])
    if version:
        return "pip3"
    version = extract_cmd_version(["pip", "--version"])
    if version:
        return "pip"
    # unable to find pip, default to pip
    return "pip"
