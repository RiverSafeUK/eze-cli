"""Sarif reporter class implementation"""

from typing import List
import uuid
from pydash import py_
from eze import __version__
from eze.core.reporter import ReporterMeta
from eze.core.enums import Vulnerability
from eze.core.tool import ScanResult
from eze.utils.io import write_sarif
from eze.utils.log import log


class SarifReporter(ReporterMeta):
    """Python report class for echoing all output into a sarif file"""

    REPORTER_NAME: str = "sarif"
    SHORT_DESCRIPTION: str = "sarif output file reporter"
    INSTALL_HELP: str = """inbuilt"""
    MORE_INFO: str = """SBOM plugins will not be exported by this reporter"""
    LICENSE: str = """inbuilt"""
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": ".eze/eze_report.sarif",
            "help_text": """report file location
By default set to eze_report.sarif""",
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return __version__

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning them into report output"""
        sarif_dict = await self._build_sarif_dict(scan_results)
        sarif_location = write_sarif(self.config["REPORT_FILE"], sarif_dict)
        log(f"Written sarif report : {sarif_location}")

    async def _build_sarif_dict(self, scan_results: list):
        """Method for parsing the scans results into sarif format"""
        sarif_schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        schema_version = "2.1.0"
        # TODO: SBOM cannot be handled by this reporter

        sarif_dict = {"$schema": sarif_schema, "version": schema_version, "runs": []}
        for scan_result in scan_results:
            tool = {"driver": {}}
            run_details = scan_result.run_details
            tool["driver"]["name"] = py_.get(run_details, "tool_name", "unknown")
            tool["driver"]["version"] = "unknown"
            tool["driver"]["fullName"] = py_.get(run_details, "tool_type", "unknown") + ":" + tool["driver"]["name"]
            if py_.get(run_details, "tool_url"):
                tool["driver"]["informationUri"] = py_.get(run_details, "tool_url")

            rules, results = self._group_vulnerabilities_into_rules(scan_result.vulnerabilities)

            tool["driver"]["rules"] = rules
            single_run = {"tool": tool, "results": results, "taxonomies": []}

            sarif_dict["runs"].append(single_run)
        return sarif_dict

    def _has_printable_vulnerabilities(self, scan_result: ScanResult) -> bool:
        """Method for taking scan vulnerabilities return True if anything to print"""
        if len(scan_result.vulnerabilities) <= 0:
            return False
        return True

    def _group_vulnerabilities_into_rules(self, vulnerabilities: List[Vulnerability]) -> tuple:
        """Method for summarizing vulnerabilities and grouping into rules"""
        if len(vulnerabilities) <= 0:
            return [], []

        rules = []
        results = []

        for idx, vulnerability in enumerate(vulnerabilities):
            rule = {
                "id": str(uuid.uuid4()),
                "name": vulnerability.name,
                "shortDescription": {"text": vulnerability.overview},
                "fullDescription": {"text": vulnerability.overview + ". " + vulnerability.recommendation},
            }
            rules.append(rule)

            result = {"ruleId": rule["id"], "ruleIndex": idx, "level": "", "message": {"text": ""}, "locations": []}

            if (
                vulnerability.severity == "critical"
                or vulnerability.severity == "high"
                or vulnerability.severity == "medium"
            ):
                result["level"] = "error"
            elif vulnerability.severity == "low":
                result["level"] = "note"
            elif vulnerability.severity == "none" or vulnerability.severity == "na":
                result["level"] = "none"
            result["message"] = {"text": vulnerability.recommendation}
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": py_.get(vulnerability.file_location, "path", "unknown")},
                    "region": {"startLine": int(py_.get(vulnerability.file_location, "line", "1"))},
                }
            }

            result["locations"].append(location)
            results.append(result)

        return rules, results
