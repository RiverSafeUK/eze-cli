"""snyk tool class"""

from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum, ToolType, SourceType
from eze.core.tool import (
    ToolMeta,
    Vulnerability,
    ScanResult,
)
from eze.utils.cli import extract_cmd_version, run_cli_command
from eze.utils.io import load_json, create_tempfile_path, delete_file


class SnykTool(ToolMeta):
    """snyk Python tool class"""

    TOOL_NAME: str = "snyk"
    TOOL_TYPE: ToolType = ToolType.SCA
    SOURCE_SUPPORT: list = [
        SourceType.RUBY,
        SourceType.NODE,
        SourceType.JAVA,
        SourceType.GRADLE,
        SourceType.SBT,
        SourceType.PYTHON,
        SourceType.GO,
    ]
    SHORT_DESCRIPTION: str = "proprietary multi language SCA scanner"
    INSTALL_HELP: str = """In most cases all that is required to install snyk is node and npm install
npm install snyk -g
snyk --version

Then ensure your snyk instance is configured
snyk auth"""
    MORE_INFO: str = """https://support.snyk.io/hc/en-us
https://docs.npmjs.com/downloading-and-installing-node-js-and-npm

note a root level .snyk should be created to configure synk
see https://support.snyk.io/hc/en-us/articles/360007487097-The-snyk-file"""
    # https://github.com/snyk/snyk/blob/master/LICENSE
    LICENSE: str = """Apache 2.0"""
    EZE_CONFIG: dict = {
        "PACKAGE_FILE": {
            "type": str,
            "help_text": """Optional run synk with --file argument
for specifying explicit or nested package file
aka a package.json, pom.xml, or requirements.txt""",
        },
        "PACKAGE_MANAGER": {
            "type": str,
            "help_text": """Optional run synk with --package-manager argument
for specifying type of package file, only needed if non-stndard name
aka pip""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-snyk-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-snyk-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
    }

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": "snyk test",
            # eze config fields -> flags
            "FLAGS": {
                "PACKAGE_FILE": "--file=",
                "PACKAGE_MANAGER": "--package-manager=",
                "REPORT_FILE": "--json-file-output=",
            },
        }
    }
    _version_cache = False

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        if SnykTool._version_cache:
            return SnykTool._version_cache

        version = extract_cmd_version("snyk --version")
        SnykTool._version_cache = version
        return version

    async def run_scan(self) -> ScanResult:
        """Method for running a synchronous scan using tool"""
        delete_file(self.config["REPORT_FILE"])
        completed_process = run_cli_command(self.TOOL_CLI_CONFIG["CMD_CONFIG"], self.config, self.TOOL_NAME)

        report_warnings = []
        if completed_process.stderr:
            report_warnings.append(completed_process.stderr)

        report_events = self.load_report()

        report = self.parse_report(report_events)
        report.warnings = report_warnings

        return report

    def load_report(self):
        """load the snyk json report"""
        report_events = load_json(self.config["REPORT_FILE"])
        return report_events

    def parse_report(self, parsed_json: dict) -> ScanResult:
        """convert report json into ScanResult

        see https://snyk.docs.apiary.io/
        """
        vulnerability_events = parsed_json["vulnerabilities"]
        vulnerabilities_list = []

        for vulnerability_event in vulnerability_events:
            module_name = vulnerability_event.get("moduleName", "") or vulnerability_event.get("packageName", "")
            vulnerable_package_name = f"""{module_name}:{vulnerability_event["title"]}"""

            installed_version = vulnerability_event.get("version", "")
            title = vulnerability_event.get("title", "")
            summary = f"{title} vulnerability in {module_name}"
            identifiers = {}
            raw_identifiers = vulnerability_event.get("identifiers", {})
            for identifier_key in raw_identifiers:
                identifier_values = raw_identifiers[identifier_key]
                # pick first identifer if multiple available
                if len(identifier_values) > 0:
                    # normalise ALTERNATIVE id to SNYK
                    if identifier_key == "ALTERNATIVE":
                        identifiers["snyk"] = identifier_values[0]
                    else:
                        identifier_key = identifier_key.lower()
                        identifiers[identifier_key] = identifier_values[0]
            if not hasattr(identifiers, "SNYK"):
                identifiers["snyk"] = vulnerability_event.get("id", "")

            severity = VulnerabilitySeverityEnum.normalise_name(vulnerability_event.get("severity", ""))

            if vulnerability_event.get("isUpgradable", ""):
                recommendation = f"""Update package '{module_name}' to non vulnerable version"""
            elif vulnerability_event.get("isPatchable", ""):
                recommendation = f"""Package '{module_name}' is patchable, patch to non vulnerable version"""
            else:
                recommendation = ""

            vulnerability = Vulnerability(
                {
                    "vulnerability_type": VulnerabilityType.dependancy.name,
                    "name": vulnerable_package_name,
                    "version": installed_version,
                    "overview": summary,
                    "recommendation": recommendation,
                    "language": vulnerability_event.get("language", ""),
                    "severity": severity,
                    "identifiers": identifiers,
                    "metadata": {},
                }
            )
            vulnerabilities_list.append(vulnerability)

        report = ScanResult(
            {
                "tool": self.TOOL_NAME,
                "vulnerabilities": vulnerabilities_list,
            }
        )
        return report


class SnykContainerTool(SnykTool):
    """snyk Python tool class"""

    TOOL_NAME: str = "snyk-container"
    TOOL_TYPE: ToolType = ToolType.SCA
    SOURCE_SUPPORT: list = [SourceType.CONTAINER]
    SHORT_DESCRIPTION: str = "proprietary container scanner"
    INSTALL_HELP: str = SnykTool.INSTALL_HELP
    MORE_INFO: str = SnykTool.MORE_INFO
    EZE_CONFIG: dict = {
        "DOCKER_TAG": {
            "type": str,
            "required": True,
            "help_text": """Required image repository to scan
Optional image repository can include tag to scan

For detailed IMAGE details
See https://support.snyk.io/hc/en-us/articles/360003946917-Test-images-with-the-Snyk-Container-CLI
""",
            "help_example": "debian:stable",
        },
        "DOCKERFILE": {
            "type": str,
            "help_text": """Optional docker file
maps to --file snyk argument""",
        },
        "PLATFORM": {
            "type": str,
            "help_text": """Optional platform
maps to --platform snyk argument""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-snyk-container-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-snyk-container-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
    }

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": "snyk container test",
            # eze config fields -> arguments
            "ARGUMENTS": ["DOCKER_TAG"],
            # eze config fields -> flags
            "FLAGS": {"DOCKERFILE": "--file=", "PLATFORM": "--platform=", "REPORT_FILE": "--json-file-output="},
        }
    }


class SnykIacTool(SnykTool):
    """snyk Python tool class"""

    TOOL_NAME: str = "snyk-iac"
    TOOL_TYPE: ToolType = ToolType.SCA
    SOURCE_SUPPORT: list = []
    SHORT_DESCRIPTION: str = "proprietary infrastructure scanner"
    INSTALL_HELP: str = SnykTool.INSTALL_HELP
    MORE_INFO: str = SnykTool.MORE_INFO
    EZE_CONFIG: dict = {
        "SOURCE": {
            "type": str,
            "required": True,
            "help_text": """Required iac setup to scan

For detailed details
See https://support.snyk.io/hc/en-us/articles/360012429477-Test-your-Kubernetes-files-with-our-CLI-tool
""",
        },
        "REPORT_FILE": {
            "type": str,
            "default": create_tempfile_path("tmp-snyk-iac-report.json"),
            "default_help_value": "<tempdir>/.eze-temp/tmp-snyk-iac-report.json",
            "help_text": "output report location (will default to tmp file otherwise)",
        },
    }

    TOOL_CLI_CONFIG = {
        "CMD_CONFIG": {
            # tool command prefix
            "BASE_COMMAND": "snyk iac test",
            # eze config fields -> arguments
            "ARGUMENTS": ["SOURCE"],
            # eze config fields -> flags
            "FLAGS": {"REPORT_FILE": "--json-file-output="},
        }
    }

    def parse_report(self, parsed_json: dict) -> ScanResult:
        """convert report json into ScanResult

        see https://snyk.docs.apiary.io/
        """
        infrastructure_events = parsed_json["infrastructureAsCodeIssues"]
        vulnerabilities_list = []
        file = f"""{parsed_json["path"]}/{parsed_json["targetFile"]}"""

        for vulnerability_event in infrastructure_events:
            module_name = vulnerability_event.get("moduleName", "") or vulnerability_event.get("packageName", "")
            vulnerable_package_name = f"""{module_name}:{vulnerability_event.get("title", "")}"""

            iac_description = vulnerability_event.get("iacDescription", {}).get("issue", "")
            iac_impact = vulnerability_event.get("impact", {}).get("resolve", "")
            summary = f"{iac_description}, {iac_impact}"
            identifiers = {"SNYK": vulnerability_event.get("id", "")}

            recommendation = vulnerability_event.get("iacDescription", "")["resolve"]
            line = vulnerability_event.get("lineNumber", "")

            vulnerability = Vulnerability(
                {
                    "vulnerability_type": VulnerabilityType.infrastructure.name,
                    "name": vulnerable_package_name,
                    "overview": summary,
                    "recommendation": recommendation,
                    "severity": vulnerability_event.get("severity", ""),
                    "is_ignored": vulnerability_event.get("isIgnored", False),
                    "identifiers": identifiers,
                    "file_location": {"path": file, "line": line},
                }
            )
            vulnerabilities_list.append(vulnerability)

        report = ScanResult(
            {
                "tool": self.TOOL_NAME,
                "vulnerabilities": vulnerabilities_list,
            }
        )
        return report
