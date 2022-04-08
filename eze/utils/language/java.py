"""helper functions for dealing with mvn and java issues"""

import re

from eze.utils.io.file_scanner import find_files_by_name


def get_maven_projects() -> []:
    """give a list of maven projects"""
    pom_files: list = find_files_by_name("^pom.xml$")
    return pom_files


def is_groovy_errors(warning_text: str) -> bool:
    """detect https://issues.apache.org/jira/browse/GROOVY-8339 error messages"""
    return (
        not warning_text.startswith("WARNING: An illegal reflective access operation has occurred")
        and not warning_text.startswith("WARNING: Illegal reflective access by")
        and not warning_text.startswith("WARNING: Please consider reporting")
        and not warning_text.startswith("WARNING: All illegal access operations")
        and not warning_text.startswith("WARNING: Use --illegal-access=warn")
        and not re.match("^\\s*$", warning_text)
    )


def ignore_groovy_errors(warnings_text: str) -> list:
    """Ignore https://issues.apache.org/jira/browse/GROOVY-8339 error messages"""
    warnings = warnings_text.split("\n")
    without_groovy_warnings = [warning for warning in warnings if is_groovy_errors(warning)]
    return without_groovy_warnings
