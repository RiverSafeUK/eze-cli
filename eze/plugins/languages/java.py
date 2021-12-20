"""Base class for java language"""
import click

from eze.core.enums import SourceType
from eze.core.language import LanguageRunnerMeta
from eze.plugins.tools.java_cyclonedx import JavaCyclonedxTool
from eze.plugins.tools.java_dependencycheck import JavaDependencyCheckTool
from eze.plugins.tools.java_spotbugs import JavaSpotbugsTool
from eze.plugins.tools.semgrep import SemGrepTool
from eze.plugins.tools.trufflehog import TruffleHogTool
from eze.utils.log import log, log_debug, log_error

from eze.utils.cli import extract_cmd_version


class JavaRunner(LanguageRunnerMeta):
    """Base class for java language"""

    LANGUAGE_NAME: str = "java"
    SOURCE_TYPE: SourceType = SourceType.JAVA
    SHORT_DESCRIPTION: str = """Java (.java, pom.xml)"""
    INSTALL_HELP: str = """Java Runner
=================================
Scan maven pom for sbom and sca analysis
and running secret and semgrep sast on raw Java files
lastly generate SBOM using cyclonedx

Tips and Tricks
=================================
requires "mvn install" ran before running maven tools,
tools are expecting pom.xml at root level"""
    MORE_INFO: str = """"""

    FILE_PATTERNS: dict = {"POM_FILE": "pom.xml$", "JAVA_FILE": ".*\\.java$"}
    FOLDER_PATTERNS: dict = {}

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        version = extract_cmd_version(["java", "--version"])
        mvn_version = extract_cmd_version(["mvn", "--version"])
        if not version:
            return "inbuilt (java: none)"
        return f"inbuilt (java: {version}, mvn:{mvn_version})"

    async def pre_test(self) -> list:
        """Method for running a pre test builds on project"""
        # AB#662: implement auto builds
        # aka mvn build
        log("Java auto build not implemented yet, see AB#662: implement auto maven build")

    def create_ezerc(self) -> dict:
        """Method for building a dynamic ezerc.toml fragment"""
        return {
            "fragment": f"""
[{self.LANGUAGE_NAME}]
# Java codebase
tools = ['{SemGrepTool.TOOL_NAME}', '{TruffleHogTool.TOOL_NAME}', '{JavaDependencyCheckTool.TOOL_NAME}', '{JavaSpotbugsTool.TOOL_NAME}', '{JavaCyclonedxTool.TOOL_NAME}']
    [{self.LANGUAGE_NAME}.{SemGrepTool.TOOL_NAME}]
    REPORT_FILE = "reports/semgrep-{self.LANGUAGE_NAME}-report.json"
    PRINT_TIMING_INFO = false
    CONFIGS = [
        "p/ci",
        "p/java",
    ]
    EXCLUDE = [
        "tests"
    ]
    [{self.LANGUAGE_NAME}.{TruffleHogTool.TOOL_NAME}]
    REPORT_FILE = "reports/truffleHog-{self.LANGUAGE_NAME}-report.json"
    SOURCE = ["."]
    NO_ENTROPY = false
    INCLUDE_FULL_REASON = true
    IGNORED_FILES = [
        ".gradle",
        ".aws",
        ".idea"
    ]
    EXCLUDE = [
        ".*(node_modules|target|build|dist)$",
        ".*\\\\.(jpe?g|png|svg|eot|ttf|exe|map|lock|woff|pytest_cache)$",
        ".*//trufflehog-report.json$",
        ".*\\\\.DS_Store"
    ]
    [{self.LANGUAGE_NAME}.{JavaDependencyCheckTool.TOOL_NAME}]
    REPORT_FILE = "reports/dependencycheck-{self.LANGUAGE_NAME}-report.json"
    
    [{self.LANGUAGE_NAME}.{JavaSpotbugsTool.TOOL_NAME}]
    REPORT_FILE = "reports/spotbugs-{self.LANGUAGE_NAME}-report.json"
    
    [{self.LANGUAGE_NAME}.{JavaCyclonedxTool.TOOL_NAME}]
    REPORT_FILE = "reports/cyclonedx-{self.LANGUAGE_NAME}-bom.json"
""",
            "message": """requires "mvn install" ran before running maven tools,
tools are expecting pom.xml at root level""",
        }
