"""Semantic version helpers for doing severity by version diffing

https://semver.org/
"""
import semantic_version

from eze.core.tool import VulnerabilitySeverityEnum


def get_severity(installed_version: str, latest_version: str, config: dict):
    """detect Severity from two version strings"""
    try:
        parsed_installed = semantic_version.Version(installed_version)
        parsed_latest = semantic_version.Version(latest_version)

        if parsed_installed.major < parsed_latest.major:
            return config["NEWER_MAJOR_SEMVERSION_SEVERITY"]
        if parsed_installed.minor < parsed_latest.minor:
            return config["NEWER_MINOR_SEMVERSION_SEVERITY"]
        if parsed_installed.patch < parsed_latest.patch:
            return config["NEWER_PATCH_SEMVERSION_SEVERITY"]
    except ValueError:
        return VulnerabilitySeverityEnum.none.name
    return VulnerabilitySeverityEnum.none.name


def get_recommendation(outdated_package: str, installed_version: str, latest_version: str):
    """create a recommendation string from two version strings"""
    recommendation = f"update {outdated_package} ({installed_version}) to a newer version"
    try:
        parsed_installed = semantic_version.Version(installed_version)
        parsed_latest = semantic_version.Version(latest_version)

        if parsed_installed.major < parsed_latest.major:
            recommendation += (
                f", current version is {parsed_latest.major - parsed_installed.major} major versions out of date"
            )
        elif parsed_installed.minor < parsed_latest.minor:
            recommendation += (
                f", current version is {parsed_latest.minor - parsed_installed.minor} minor versions out of date"
            )
        elif parsed_installed.patch < parsed_latest.patch:
            recommendation += (
                f", current version is {parsed_latest.patch - parsed_installed.patch} patch versions out of date"
            )
    except ValueError:
        pass

    recommendation += f". Latest is {latest_version}"

    return recommendation
