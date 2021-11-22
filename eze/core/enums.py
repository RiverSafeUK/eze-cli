# pylint: disable=invalid-name

"""Eze's core enums module"""
from enum import Enum


class VulnerabilitySeverityEnum(Enum):
    """Enum for severity"""

    critical = 0
    high = 1
    medium = 2
    low = 3
    none = 4
    na = 5

    @staticmethod
    def normalise_name(value: str, default="na") -> str:
        """Normalise the name of the enum"""
        if hasattr(VulnerabilitySeverityEnum, value):
            return value
        return default


class VulnerabilityType(Enum):
    """Enum for Vulnerability Type"""

    generic = "GENERIC VULNERABILITY"
    dependancy = "DEPENDANCY VULNERABILITY"
    code = "CODE BEST PRACTICE OR VULNERABILITY"
    infrastructure = "INFRASTRUCTURE VULNERABILITY"
    secret = "SECRET VULNERABILITY"  # nosec

    @staticmethod
    def normalise_name(value: str, default="generic") -> str:
        """Normalise the name of the enum"""
        if hasattr(VulnerabilityType, value):
            return value
        return default


class ToolType(Enum):
    """Enum for Tool Type"""

    SBOM = "SBOM"  # Bill of Materials Tool
    SCA = "SCA"  # Software Composition Analysis
    SAST = "SAST"  # Insecure Code Scanners
    SECRET = "SECRET"  # Secrets Scanner
    MISC = "MISC"  # Other type of Scanner


class SourceType(Enum):
    """Enum for Source Type"""

    ALL = "ALL"  # Generic supports all source type
    PYTHON = "PYTHON"  # Python project
    NODE = "NODE"  # Node project
    JAVA = "JAVA"  # Java Maven project
    GRADLE = "GRADLE"  # Java Gradle project
    SBT = "SBT"  # Java / Scala SBT project
    RUBY = "RUBY"  # Ruby project
    GO = "GO"  # Golang project
    PHP = "PHP"  # PHP project
    CONTAINER = "CONTAINER"  # Dockerfile / Container project
