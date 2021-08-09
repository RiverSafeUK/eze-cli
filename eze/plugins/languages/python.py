"""Python Language Runner module"""
import click

from eze.core.enums import SourceType
from eze.core.language import LanguageRunnerMeta
from eze.plugins.tools.python_bandit import BanditTool
from eze.plugins.tools.python_cyclonedx import PythonCyclonedxTool
from eze.plugins.tools.python_piprot import PiprotTool
from eze.plugins.tools.python_safety import SafetyTool
from eze.plugins.tools.semgrep import SemGrepTool
from eze.plugins.tools.trufflehog import TruffleHogTool
from eze.utils.cli import extract_cmd_version
from eze.utils.io import pretty_print_json

from pydash import py_


class PythonRunner(LanguageRunnerMeta):
    """Base class for python language runner"""

    LANGUAGE_NAME: str = "python"
    SOURCE_TYPE: SourceType = SourceType.PYTHON
    SHORT_DESCRIPTION: str = "Python (.py, requirements.txt)"
    INSTALL_HELP: str = """Python Runner
=================================
Scan pip packages for old and vulnerable packages
and running secret and semgrep sast on raw python files
lastly generate SBOM using cyclonedx

Tips and Tricks
=================================
Safety and Piprot work best when running against pip frozen requirements"""
    MORE_INFO: str = """https://www.python.org/"""

    FILE_PATTERNS: dict = {"REQUIREMENTS": "requirements.txt$", "PYTHON_FILE": ".*\\.py$"}
    FOLDER_PATTERNS: dict = {}

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        version = extract_cmd_version(["python", "--version"])
        pip_version = extract_cmd_version(["pip", "--version"])
        if not version:
            return "inbuilt (python: none)"
        return f"inbuilt (python: {version}, pip:{pip_version})"

    async def pre_test(self) -> list:
        """Method for running a pre test builds on project"""
        # AB#662: implement auto builds
        # aka pip install
        click.echo("Python auto build not implemented yet, see AB#662: implement auto python build")
        click.echo("Will build frozen requirements file for safety and piprot")

    def create_ezerc(self) -> dict:
        """Method for building a dynamic ezerc.toml fragment"""
        requirement_txt_files = pretty_print_json(self.discovery.files["REQUIREMENTS"])
        # TODO: decide: if no requirements file found what to do
        first_requirement_txt = py_.get(self.discovery.files["REQUIREMENTS"], "[0]", "requirements.txt")
        requirement_txt_file = pretty_print_json(first_requirement_txt)
        return {
            "fragment": f"""
[{self.LANGUAGE_NAME}]
# Python codebase
REQUIREMENTS_FILES = {requirement_txt_files}
tools = ['{SemGrepTool.TOOL_NAME}', '{TruffleHogTool.TOOL_NAME}', '{BanditTool.TOOL_NAME}', '{PiprotTool.TOOL_NAME}', '{SafetyTool.TOOL_NAME}', '{PythonCyclonedxTool.TOOL_NAME}']
    [{self.LANGUAGE_NAME}.{SemGrepTool.TOOL_NAME}]
    REPORT_FILE = "reports/semgrep-{self.LANGUAGE_NAME}-report.json"
    PRINT_TIMING_INFO = true
    CONFIGS = [
        "p/ci",
        "p/python",
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
    
    [{self.LANGUAGE_NAME}.{BanditTool.TOOL_NAME}]
    REPORT_FILE = "reports/bandit-{self.LANGUAGE_NAME}-report.json"
    IGNORE_BELOW_SEVERITY = "medium"
    SOURCE = "."
    
    [{self.LANGUAGE_NAME}.{PiprotTool.TOOL_NAME}]
    REPORT_FILE = "reports/piprot-{self.LANGUAGE_NAME}-report.json"
    NEWER_MAJOR_SEMVERSION_SEVERITY = "medium"
    NEWER_MINOR_SEMVERSION_SEVERITY = "none"
    NEWER_PATCH_SEMVERSION_SEVERITY = "none"
    IGNORE_BELOW_SEVERITY = "low"
    
    [{self.LANGUAGE_NAME}.{SafetyTool.TOOL_NAME}]
    # By default it uses the open Python vulnerability database Safety DB, 
    # but can be upgraded to use pyup.io's Safety API using the APIKEY option
    # see https://github.com/pyupio/safety/blob/master/docs/api_key.md
    REPORT_FILE = "reports/safety-{self.LANGUAGE_NAME}-report.json"
    
    [{self.LANGUAGE_NAME}.{PythonCyclonedxTool.TOOL_NAME}]
    REPORT_FILE = "reports/cyclonedx-{self.LANGUAGE_NAME}-bom.json"
    REQUIREMENTS_FILE = {requirement_txt_file}
""",
            "message": f"""Safety and Piprot work best when running against pip frozen requirements""",
        }
