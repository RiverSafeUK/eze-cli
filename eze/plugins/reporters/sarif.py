"""Sarif reporter class implementation"""

from typing import List
import uuid
from pydash import py_
import click
from eze import __version__
from eze.core.reporter import ReporterMeta
from eze.core.tool import ScanResult, Vulnerability
from eze.utils.io import write_sarif


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
            "default": "eze_report.sarif",
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
        sarif_str = await self._build_sarif_str(scan_results)
        sarif_location = write_sarif(self.config["REPORT_FILE"], sarif_str)
        print(f"Written sarif report : {sarif_location}")

    async def _build_sarif_str(self, scan_results: list):
        """Method for parsing the scans results into sarif format"""
        sarif_schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        schema_version = "2.1.0"
        click.echo("Eze report results:\n")
        scan_results_with_sboms = []

        sarif_str = {"$schema": sarif_schema, "version": schema_version, "runs": []}
        for scan_result in scan_results:
            tool = {"driver": {}}
            # print_scan_summary_title() ??
            if self._has_printable_vulnerabilities(scan_result):
                run_details = scan_result.run_details

                tool["driver"]["name"] = py_.get(run_details, "tool_name", "unknown")
                tool["driver"]["version"] = "unknown"
                tool["driver"]["fullName"] = (
                    py_.get(run_details, "tool_type", "unknown")
                    + ":"
                    + py_.get(run_details, "short_description", "unknown")
                )
                tool["driver"]["informationUri"] = py_.get(run_details, "tool_url", "unknown")

                rules, results, severity_counters = self._group_vulnerabilities_into_rules(scan_result.vulnerabilities)

                tool["driver"]["rules"] = rules
                single_run = {
                    "tool": tool,
                    "results": results,
                    "taxonomies": [],
                    "severity_counters": severity_counters,
                }

                sarif_str["runs"].append(single_run)

            if scan_result.bom:
                scan_results_with_sboms.append(
                    scan_result
                )  # TODO: SBOM cannot be handle by this reporter, so its skipped.
        return sarif_str

    def _has_printable_vulnerabilities(self, scan_result: ScanResult) -> bool:
        """Method for taking scan vulnerabilities return True if anything to print"""
        if len(scan_result.vulnerabilities) <= 0:
            return False
        return True

    def _group_vulnerabilities_into_rules(self, vulnerabilities: List[Vulnerability]) -> list:
        """Method for summarizing vulnerabilities and grouping into rules"""
        if len(vulnerabilities) <= 0:
            return {}, {}

        rules = []
        results = []
        severity_counters = {}
        for idx, vulnerability in enumerate(vulnerabilities):
            rule = {}
            rule["id"] = str(uuid.uuid4())
            rule["name"] = vulnerability.name
            rule["shortDescription"] = {"text": vulnerability.overview}
            rule["fullDescription"] = {"text": vulnerability.overview + ". " + vulnerability.recommendation}
            rules.append(rule)

            result = {"ruleId": "", "ruleIndex": -1, "level": "", "message": {"text": ""}, "locations": []}
            result["ruleId"] = rule["id"]
            result["ruleIndex"] = idx

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
            result["locations"].append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": py_.get(vulnerability.file_location, "path", "unknown")},
                        "region": {"startLine": py_.get(vulnerability.file_location, "line", "unknown")},
                    }
                }
            )
            results.append(result)
            if vulnerability.severity not in severity_counters:
                severity_counters[vulnerability.severity] = 0
            severity_counters[vulnerability.severity] += 1

        return rules, results, severity_counters
