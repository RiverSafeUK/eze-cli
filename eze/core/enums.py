# pylint: disable=invalid-name

"""Eze's core enums module"""
from enum import Enum
from pydash import py_
from eze.utils.config import get_config_key
from eze.utils.io.file import normalise_linux_file_path


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
    dependency = "DEPENDENCY VULNERABILITY"
    license = "LICENSE RISK"
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
    BASH = "BASH"  # Bash files
    NODE = "NODE"  # Node project
    DOTNET = "DOTNET"  # C# and Dot Net project
    JAVA = "JAVA"  # Java Maven project
    GRADLE = "GRADLE"  # Java Gradle project
    SBT = "SBT"  # Java / Scala SBT project
    RUBY = "RUBY"  # Ruby project
    GO = "GO"  # Golang project
    PHP = "PHP"  # PHP project
    CONTAINER = "CONTAINER"  # Dockerfile / Container project


class LicenseScanType(Enum):
    """Enum for License Scan Type"""

    PROPRIETARY = "PROPRIETARY"  # for commercial projects, check for non-commercial, strong-copyleft, and source-available licenses
    PERMISSIVE = "PERMISSIVE"  # for permissive open source projects (aka MIT, LGPL), check for strong-copyleft licenses
    OPENSOURCE = (
        "OPENSOURCE"  # for copyleft open source projects (aka GPL), check for non-OSI or FsfLibre certified licenses
    )
    OFF = "OFF"  # no license checks


LICENSE_CHECK_CONFIG = {
    "type": str,
    "default": LicenseScanType.PROPRIETARY.value,
    "help_text": """available modes:
- PROPRIETARY : for commercial projects, check for non-commercial, strong-copyleft, and source-available licenses
- PERMISSIVE : for permissive open source projects (aka MIT, LGPL), check for strong-copyleft licenses
- OPENSOURCE : for copyleft open source projects (aka GPL), check for non-OSI or FsfLibre certified licenses
- OFF : no license checks
All modes will also warn on "unprofessional", "deprecated", and "permissive with conditions" licenses""",
    "help_example": "PROPRIETARY",
}

LICENSE_CHECK_CONFIG = {
    "type": str,
    "default": LicenseScanType.PROPRIETARY.value,
    "help_text": """available modes:
- PROPRIETARY : for commercial projects, check for non-commercial, strong-copyleft, and source-available licenses
- PERMISSIVE : for permissive open source projects (aka MIT, LGPL), check for strong-copyleft licenses
- OPENSOURCE : for copyleft open source projects (aka GPL), check for non-OSI or FsfLibre certified licenses
- OFF : no license checks
All modes will also warn on "unprofessional", "deprecated", and "permissive with conditions" licenses""",
    "help_example": "PROPRIETARY",
}

LICENSE_ALLOWLIST_CONFIG = {
    "type": list,
    "default": [],
    "help_text": """list of licenses to exempt from license checks""",
    "help_example": ["MIT-enna"],
}

LICENSE_DENYLIST_CONFIG = {
    "type": list,
    "default": [],
    "help_text": """list of licenses to always report usage as a error""",
    "help_example": ["MIT-enna"],
}


class Vulnerability:
    """Wrapper around raw dict to provide easy code typing"""

    def __init__(self, vo: dict):
        """constructor"""
        # aka generic / dependency / secret
        self.vulnerability_type: str = get_config_key(vo, "vulnerability_type", str, VulnerabilityType.generic.name)
        # package name for SCA
        # file name for SAST
        self.name: str = get_config_key(vo, "name", str, "")
        # description of issue for SCA/SAST
        self.overview: str = get_config_key(vo, "overview", str, "")
        # [optional] mitigation recommendations for SCA/SAST
        self.recommendation: str = get_config_key(vo, "recommendation", str, "")
        self.severity: str = get_config_key(vo, "severity", str, "").lower()
        self.confidence: str = get_config_key(vo, "confidence", str, "").lower()
        self.is_ignored: bool = get_config_key(vo, "is_ignored", bool, False)
        self.is_excluded: bool = get_config_key(vo, "is_excluded", bool, False)
        # [optional] containers cve/cwe info
        self.identifiers: dict = get_config_key(vo, "identifiers", dict, {})
        # [optional] pair of File/Line
        self.file_location: dict = get_config_key(vo, "file_location", dict, None)
        # [optional] version of object under test
        self.version: str = get_config_key(vo, "version", str, "")
        # [optional] list of reference urls
        self.references: list = get_config_key(vo, "references", list, [])
        # misc container
        self.metadata: dict = get_config_key(vo, "metadata", dict, None)

    def update_ignored(self, tool_config: dict) -> bool:
        """detect if vulnerability is to be ignored"""
        # TODO: move function to util
        if self.is_ignored:
            self.is_ignored = True
            return True
        if self.name in tool_config["IGNORED_VULNERABILITIES"]:
            self.is_ignored = True
            return True
        for identifier_key in self.identifiers:
            identifier_value = self.identifiers[identifier_key]
            if identifier_value in tool_config["IGNORED_VULNERABILITIES"]:
                self.is_ignored = True
                return True
        file_location = py_.get(self, "file_location.path", False)
        if file_location:
            file_location = normalise_linux_file_path(file_location)
            for ignored_path in tool_config["IGNORED_FILES"]:
                if file_location.startswith(ignored_path):
                    self.is_ignored = True
                    return True
        severity_level = VulnerabilitySeverityEnum[self.severity].value
        if severity_level > tool_config["IGNORE_BELOW_SEVERITY_INT"]:
            self.is_ignored = True
            return True
        self.is_ignored = False
        return False

    def update_excluded(self, tool_config: dict) -> bool:
        """detect if vulnerability is to be excluded"""
        # TODO: move function to util
        if self.is_excluded:
            self.is_excluded = True
            return True

        file_location = py_.get(self, "file_location.path", False)
        if file_location:
            file_location = normalise_linux_file_path(file_location)
            for excluded_path in tool_config["EXCLUDE"]:
                if file_location.startswith(excluded_path):
                    self.is_excluded = True
                    return True

        self.is_excluded = False
        return False


class Component:
    """Wrapper around raw dict to provide easy code typing, for annotated cyclonedx sbom components"""

    def __init__(self, vo: dict):
        """constructor"""
        self.type: str = get_config_key(vo, "type", str, "")
        self.name: str = get_config_key(vo, "name", str, "")
        self.version: str = get_config_key(vo, "version", str, "")
        self.description: str = get_config_key(vo, "description", str, "")
        self.is_transitive = get_config_key(vo, "is_transitive", bool, False)
        self.license: str = get_config_key(vo, "license", str, "unknown")
        self.license_type: str = get_config_key(vo, "license_type", str, "unknown")
        self.license_is_professional: str = get_config_key(vo, "license_is_professional", bool, None)
        self.license_is_osi_approved: str = get_config_key(vo, "license_is_osi_approved", bool, None)
        self.license_is_fsf_libre: str = get_config_key(vo, "license_is_fsf_libre", bool, None)
        self.license_is_deprecated: str = get_config_key(vo, "license_is_deprecated", bool, None)
