"""cyclonedx SBOM tool class"""
import re
import shlex

from eze.utils.log import log_debug

from eze.utils.io.file_scanner import find_files_by_name

from eze.core.enums import ToolType, SourceType, LICENSE_CHECK_CONFIG, LICENSE_ALLOWLIST_CONFIG, LICENSE_DENYLIST_CONFIG
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli.run import run_async_cli_command
from eze.utils.io.file import create_tempfile_path, load_json
from eze.utils.scan_result import convert_multi_sbom_into_scan_result
from eze.utils.data.pypi import pypi_sca_sboms


class PythonCyclonedxTool(ToolMeta):
    """cyclonedx python bill of materials generator & vulnerability detection tool (SBOM/SCA) tool class"""

    TOOL_NAME: str = "python-cyclonedx"
    TOOL_URL: str = "https://cyclonedx.org/"
    TOOL_TYPE: ToolType = ToolType.SBOM
    SOURCE_SUPPORT: list = [SourceType.PYTHON]
    SHORT_DESCRIPTION: str = "opensource python bill of materials (SBOM) generation utility, also runs SCA via pypi"
    INSTALL_HELP: str = """In most cases all that is required is python and pip (version 3+), and cyclonedx installed via pip

pip install cyclonedx-bom"""
    MORE_INFO: str = """https://github.com/CycloneDX/cyclonedx-python
https://owasp.org/www-project-cyclonedx/
https://cyclonedx.org/

Will automatically run against any poetry, requirements.txt, and pipenv projects in the repo

Common Gotchas
===========================
requirements.txt Pip Freezing

A bill-of-material such as CycloneDX expects exact version numbers. Therefore requirements.txt must be frozen. 

This can be accomplished via:

$ pip freeze > requirements.txt
"""
    # https://github.com/CycloneDX/cyclonedx-python/blob/master/LICENSE
    LICENSE: str = """Apache-2.0"""
    VERSION_CHECK: dict = {"FROM_EXE": "cyclonedx-py", "FROM_PIP": "cyclonedx-bom"}
    EZE_CONFIG: dict = {
        "REQUIREMENTS_FILES": {
            "type": list,
            "default": [],
            "help_text": """surplus custom requirements.txt file
any requirements files named requirements.txt or requirements-dev.txt will be automatically collected
gotcha: make sure it's a frozen version of the pip requirements""",
            "help_example": "[custom-requirements.txt]",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-python-cyclonedx-bom.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-python-cyclonedx-bom.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
        "SCA_ENABLED": {
            "type": bool,
            "default": True,
            "help_text": "use pypi and nvd data feeds to Pypi detect vulnerabilities",
        },
        "LICENSE_CHECK": LICENSE_CHECK_CONFIG.copy(),
        "LICENSE_ALLOWLIST": LICENSE_ALLOWLIST_CONFIG.copy(),
        "LICENSE_DENYLIST": LICENSE_DENYLIST_CONFIG.copy(),
    }

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": shlex.split("cyclonedx-py --format=json --force"),
            # eze config fields -> flags
            "FLAGS": {
                "PACKAGE_FILE": "-i=",
                "REPORT_FILE": "-o=",
            },
            # eze config fields -> flags
            "SHORT_FLAGS": {"REQUIREMENTS_FILE": "-r", "PIPLOCK_FILE": "-pip", "POETRY_FILE": "-p"},
        }
    }

    def extract_unpinned_requirements(self, stdout_output: str) -> list:
        """Extract the unpinned requirement from stdout of python-cyclonedx"""
        pattern = re.compile(r"(?<=->\s)(.*?)(?=\s*!!)")
        matches = pattern.finditer(stdout_output)

        results = []
        for match in matches:
            results.append(
                f"Warning: unpinned requirement '{match.group()}' found in requirements.txt, unable to check"
            )
        return results

    async def run_scan(self) -> ScanResult:
        """
        Method for running a synchronous scan using tool

        :raises EzeError
        """
        warnings_list = []
        sboms = {}
        requirements_files = find_files_by_name("requirements.txt")
        requirements_files.extend(find_files_by_name("requirements-dev.txt"))
        requirements_files.extend(self.config["REQUIREMENTS_FILES"])
        poetry_files = find_files_by_name("poetry.lock")
        piplock_files = find_files_by_name("Pipfile.lock")

        has_found_packages: bool = False

        for requirements_file in requirements_files:
            log_debug(f"run 'cyclonedx-py' on {requirements_file}")
            [warnings, cyclonedx_bom] = await self.run_individual_scan(
                {"PACKAGE_FILE": requirements_file, "REQUIREMENTS_FILE": True}
            )
            warnings_list.extend(warnings)
            sboms[requirements_file] = cyclonedx_bom
            has_found_packages = True

        for poetry_file in poetry_files:
            log_debug(f"run 'cyclonedx-py' on {poetry_file}")
            [warnings, cyclonedx_bom] = await self.run_individual_scan(
                {"PACKAGE_FILE": poetry_file, "POETRY_FILE": True}
            )
            warnings_list.extend(warnings)
            sboms[poetry_file] = cyclonedx_bom
            has_found_packages = True

        for piplock_file in piplock_files:
            log_debug(f"run 'cyclonedx-py' on {piplock_file}")
            [warnings, cyclonedx_bom] = await self.run_individual_scan(
                {"PACKAGE_FILE": piplock_file, "PIPLOCK_FILE": True}
            )
            warnings_list.extend(warnings)
            sboms[piplock_file] = cyclonedx_bom
            has_found_packages = True

        if not has_found_packages:
            warnings_list.append("cyclonedx-py not ran, no python packages found")

        report = self.parse_report(sboms)
        report.warnings.extend(warnings_list)

        return report

    async def run_individual_scan(self, settings) -> list:
        """run individual scan of cyclonedx"""
        warnings = []
        scan_config = self.config.copy()
        scan_config = {**settings, **scan_config}
        completed_process = await run_async_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], scan_config, self.TOOL_NAME)
        cyclonedx_bom = load_json(self.config["REPORT_FILE"])
        if "Some of your dependencies do not have pinned version" in completed_process.stdout:
            unpinned_requirements_list = self.extract_unpinned_requirements(completed_process.stdout)
            for unpinned_requirement in unpinned_requirements_list:
                warnings.append(unpinned_requirement)
        if completed_process.stderr:
            warnings.append(completed_process.stderr)
        return [warnings, cyclonedx_bom]

    def parse_report(self, cyclonedx_boms: dict) -> ScanResult:
        """convert report json into ScanResult"""
        is_sca_enabled = self.config.get("SCA_ENABLED", False)
        scan_result: ScanResult = convert_multi_sbom_into_scan_result(self, cyclonedx_boms)
        if not is_sca_enabled:
            return scan_result
        # When SCA_ENABLED get SCA vulnerabilities/warnings directly from PYPI
        [pypi_vulnerabilities, pypi_warnings] = pypi_sca_sboms(cyclonedx_boms)
        scan_result.vulnerabilities.extend(pypi_vulnerabilities)
        scan_result.warnings.extend(pypi_warnings)

        return scan_result
