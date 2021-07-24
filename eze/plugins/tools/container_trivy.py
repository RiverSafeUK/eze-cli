"""Trivy Container tool class"""

from pydash import py_

from eze.core.config import ConfigException
from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum, ToolType, SourceType
from eze.core.tool import (
    ToolMeta,
    Vulnerability,
    ScanResult,
)
from eze.utils.cli import extract_cmd_version, run_cli_command
from eze.utils.io import load_json, create_tempfile_path, create_folder


class TrivyTool(ToolMeta):
    """SCA Container scanning tool Trivy tool class"""

    TOOL_NAME: str = "container-trivy"
    TOOL_TYPE: ToolType = ToolType.SCA
    SOURCE_SUPPORT: list = [SourceType.CONTAINER]
    SHORT_DESCRIPTION: str = "opensource container scanner"
    INSTALL_HELP: str = """In most cases all that is required to install trivy via apt-get or docker
As of writing, no native windows 10 trivy exists, can be run via wsl2
https://aquasecurity.github.io/trivy/latest/installation/
"""
    MORE_INFO: str = """https://aquasecurity.github.io/trivy/latest/

Tips
===========================
- use slim versions of base images
- always create a application user for running entry_point and cmd commands
- read https://owasp.org/www-project-docker-top-10/

Common Gotchas
===========================
Worth mentioning vulnerability counts are quite high for offical out the box docker images

trivy image node:slim
Total: 101 (UNKNOWN: 2, LOW: 67, MEDIUM: 8, HIGH: 20, CRITICAL: 4)

trivy image python:3.8-slim
Total: 112 (UNKNOWN: 2, LOW: 74, MEDIUM: 11, HIGH: 21, CRITICAL: 4)"""
    # https://github.com/aquasecurity/trivy/blob/main/LICENSE
    LICENSE: str = """Apache 2.0"""
    EZE_CONFIG: dict = {
        "DOCKER_TAG": {
            "type": str,
            "default": "",
            "help_text": """docker image tag to scan
Note: Required IMAGE or IMAGE_FILE""",
            "help_example": "aquasec/trivy",
        },
        "IMAGE_FILE": {
            "type": str,
            "default": "",
            "help_text": """image file to scan, maps to trivy argument -i
Note: Required IMAGE or IMAGE_FILE""",
            "help_example": "docker-image.tar",
        },
        "TRIVY_VULN_TYPE": {
            "type": list,
            "default": ["os", "library"],
            "help_text": """By default standard trivy image of "os,library", maps to trivy argument
  --vuln-type value  comma-separated list of vulnerability types (os,library) (default: "os,library")""",
        },
        "TRIVY_IGNORE_UNFIXED": {
            "type": str,
            "default": "false",
            "help_text": """By default false, maps to trivy argument
  --ignore-unfixed  display only fixed vulnerabilities (default: false) [$TRIVY_IGNORE_UNFIXED]""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-trivy-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-trivy-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
    }

    TOOL_LANGUAGE = "container"
    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": "trivy image --no-progress --format=json",
            # eze config fields -> arguments
            "TAIL_ARGUMENTS": ["IMAGE"],
            # eze config fields -> flags
            "FLAGS": {
                "TRIVY_VULN_TYPE": "--vuln-type=",
                "TRIVY_IGNORE_UNFIXED": "--ignore-unfixed=",
                "REPORT_FILE": "-o=",
                "IMAGE_FILE": "-i=",
            },
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        version = extract_cmd_version("trivy --version")
        return version

    async def run_scan(self) -> ScanResult:
        """Method for running a synchronous scan using tool"""
        # AB#608: create report folder
        report_path = self.config["REPORT_FILE"]
        create_folder(report_path)

        completed_process = run_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME)

        report_events = load_json(self.config["REPORT_FILE"])
        report = self.parse_report(report_events)
        report.warnings = []
        if completed_process.stderr:
            report.warnings.append(completed_process.stderr)

        return report

    def trivy_severity_to_cwe_severity(self, trivy_severity: str) -> str:
        """convert trivy severities into standard cvss severity

        as per
        https://semgrep.dev/docs/writing-rules/rule-syntax/#schema
        https://nvd.nist.gov/vuln-metrics/cvss"""
        trivy_severity = trivy_severity.lower()
        has_severity = hasattr(VulnerabilitySeverityEnum, trivy_severity)
        if not has_severity:
            if trivy_severity == "$unknown" or trivy_severity == "unknown":
                return VulnerabilitySeverityEnum.na.name
            print(f"ERR: unknown trivy severity '{trivy_severity}', defaulting to na")
            return VulnerabilitySeverityEnum.na.name

        return VulnerabilitySeverityEnum[trivy_severity].name

    def parse_report(self, parsed_json: list) -> ScanResult:
        """convert report json into ScanResult"""
        report_events = py_.get(parsed_json, "[0].Vulnerabilities", [])
        vulnerabilities_list = []
        for report_event in report_events:
            vulnerable_package = py_.get(report_event, "PkgName", "unknown")
            installed_version = py_.get(report_event, "InstalledVersion", "unknown")
            fixed_version = py_.get(report_event, "FixedVersion", "")
            if fixed_version:
                recommendation = f"Update {vulnerable_package} ({installed_version}) to a non vulnerable version, issue fixed in {fixed_version}"
            else:
                recommendation = ""

            identifiers = {}
            cve_id = py_.get(report_event, "VulnerabilityID", "")
            cwe_id = py_.get(report_event, "CweIDs[0]", "")
            if cve_id:
                identifiers["cve"] = cve_id
            if cwe_id:
                identifiers["cwe"] = cwe_id

            references = py_.get(report_event, "References", [])
            references.insert(0, py_.get(report_event, "PrimaryURL", ""))

            trivy_severity = py_.get(report_event, "Severity", "unknown")
            severity = self.trivy_severity_to_cwe_severity(trivy_severity)

            vulnerability_raw = {
                "vulnerability_type": VulnerabilityType.dependancy.name,
                "name": py_.get(report_event, "Title", py_.get(report_event, "PkgName", "unknown")),
                "version": py_.get(report_event, "InstalledVersion", "unknown"),
                "overview": py_.get(report_event, "Description", "unknown"),
                "recommendation": recommendation,
                "language": self.TOOL_LANGUAGE,
                "severity": severity,
                "identifiers": identifiers,
                "references": references,
            }
            vulnerability = Vulnerability(vulnerability_raw)
            vulnerabilities_list.append(vulnerability)

        report = ScanResult(
            {
                "tool": self.TOOL_NAME,
                "vulnerabilities": vulnerabilities_list,
            }
        )
        return report

    def _parse_config(self, eze_config: dict) -> dict:
        """take raw config dict and normalise values"""
        parsed_config = super()._parse_config(eze_config)

        # ADDITION PARSING: IMAGE or IMAGE_FILE
        if not parsed_config.get("DOCKER_TAG") and not parsed_config.get("IMAGE_FILE"):
            raise ConfigException(f"required param 'DOCKER_TAG' or 'IMAGE_FILE' missing from configuration")

        # ADDITION PARSING: VULNERABILITY_TYPES
        # convert to space seperated, clean os specific regex
        if len(parsed_config["TRIVY_VULN_TYPE"]) > 0:
            parsed_config["TRIVY_VULN_TYPE"] = ",".join(parsed_config["TRIVY_VULN_TYPE"])
        else:
            parsed_config["TRIVY_VULN_TYPE"] = ""

        return parsed_config
