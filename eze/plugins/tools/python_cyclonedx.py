"""cyclonedx SBOM tool class"""
import re
import shlex

from pydash import py_

from eze.core.enums import ToolType, SourceType, LICENSE_CHECK_CONFIG, LICENSE_ALLOWLIST_CONFIG, LICENSE_DENYLIST_CONFIG
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.cli import detect_pip_executable_version, run_async_cli_command
from eze.utils.io import create_tempfile_path, load_json, pretty_print_json
from eze.utils.scan_result import convert_sbom_into_scan_result
from eze.utils.purl import purl_to_components, PurlBreakdown
from eze.utils.pypi import get_pypi_package_data, PypiPackageVO


class PythonCyclonedxTool(ToolMeta):
    """cyclonedx python bill of materials generator tool (SBOM) tool class"""

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

Common Gotchas
===========================
Pip Freezing

A bill-of-material such as CycloneDX expects exact version numbers. Therefore requirements.txt must be frozen. 

This can be accomplished via:

$ pip freeze > requirements.txt
"""
    # https://github.com/CycloneDX/cyclonedx-python/blob/master/LICENSE
    LICENSE: str = """Apache-2.0"""
    EZE_CONFIG: dict = {
        "REQUIREMENTS_FILE": {
            "type": str,
            "default": "",
            "help_text": """defaults to requirements.txt
gotcha: make sure it's a frozen version of the pip requirements""",
            "help_example": "requirements.txt",
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
            "help_text": "use pypi and nvd data feeds to detect vulnerabilities",
        },
        "LICENSE_CHECK": LICENSE_CHECK_CONFIG.copy(),
        "LICENSE_ALLOWLIST": LICENSE_ALLOWLIST_CONFIG.copy(),
        "LICENSE_DENYLIST": LICENSE_DENYLIST_CONFIG.copy(),
    }

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": shlex.split("cyclonedx-py -r --format=json --force"),
            # eze config fields -> flags
            "FLAGS": {
                "REQUIREMENTS_FILE": "-i=",
                "REPORT_FILE": "-o=",
            },
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        return detect_pip_executable_version("cyclonedx-bom", "cyclonedx-py")

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

        completed_process = await run_async_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME)

        cyclonedx_bom = load_json(self.config["REPORT_FILE"])
        report = self.parse_report(cyclonedx_bom)
        if "Some of your dependencies do not have pinned version" in completed_process.stdout:
            unpinned_requirements_list = self.extract_unpinned_requirements(completed_process.stdout)
            for unpinned_requirement in unpinned_requirements_list:
                report.warnings.append(unpinned_requirement)

        if completed_process.stderr:
            report.warnings.append(completed_process.stderr)

        return report

    def parse_report(self, cyclonedx_bom: dict) -> ScanResult:
        """convert report json into ScanResult"""
        is_sca_enabled = self.config.get("SCA_ENABLED", False)
        vulnerabilities: list = []
        warnings: list = []
        if not is_sca_enabled:
            scan_result: ScanResult = convert_sbom_into_scan_result(
                self, cyclonedx_bom, self.config["REQUIREMENTS_FILE"]
            )
            return scan_result
        for component in py_.get(cyclonedx_bom, "components", []):
            purl = py_.get(component, "purl")
            purl_breakdown: PurlBreakdown = purl_to_components(purl)
            if not purl_breakdown or purl_breakdown.type != "pypi":
                continue
            pypi_data: PypiPackageVO = get_pypi_package_data(purl_breakdown.name, purl_breakdown.version)
            vulnerabilities.extend(pypi_data.vulnerabilities)
            warnings.extend(pypi_data.warnings)
            licenses = component.get("licenses", [])
            if len(licenses) == 0:
                for pypi_license in pypi_data.licenses:
                    licenses.append({"license": {"name": pypi_license}})
                component["licenses"] = licenses
        scan_result: ScanResult = convert_sbom_into_scan_result(self, cyclonedx_bom, self.config["REQUIREMENTS_FILE"])
        scan_result.vulnerabilities.extend(vulnerabilities)
        scan_result.warnings.extend(warnings)
        return scan_result
