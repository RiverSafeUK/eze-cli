"""Sarif reporter class implementation"""

import uuid
from pydash import py_
import click
from eze import __version__
from eze.core.reporter import ReporterMeta
from eze.core.enums import VulnerabilitySeverityEnum
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
        scan_results_with_warnings = []

        sarif_str = {"$schema": sarif_schema, "version": schema_version, "runs": []}

        for scan_result in scan_results:
            tool = {"driver": {}}
            # print_scan_summary_title() ??
            if self._has_printable_vulnerabilities(scan_result):
                run_details = scan_result.run_details

                tool["driver"]["name"] = py_.get(run_details, "tool_name", "unknown")
                tool["driver"]["version"] = "unknown"
                tool["driver"]["fullName"] = py_.get(run_details, "tool_type", "unknown") + ":" + tool["driver"]["name"]
                tool["driver"]["informationUri"] = "unknown"

                rules, results = self._group_vulnerabilities_into_rules(scan_result.vulnerabilities)

                tool["driver"]["rules"] = rules
                single_run = {"tool": {}, "artifacts": [], "results": [], "taxonomies": []}
                single_run["tool"] = tool
                single_run["results"] += results

                sarif_str["runs"].append(single_run)

            if scan_result.bom:
                scan_results_with_sboms.append(
                    scan_result
                )  # TODO: SBOM cannot be handle by this reporter, so its skipped.

            if len(scan_result.warnings) > 0:
                scan_results_with_warnings.append(scan_result)

            sarif_str["runs"].append(self._print_scan_report_warnings(scan_results_with_warnings))

        return sarif_str

    def _has_printable_vulnerabilities(self, scan_result: ScanResult) -> bool:
        """Method for taking scan vulnerabilities return True if anything to print"""
        if len(scan_result.vulnerabilities) <= 0:
            return False
        return True

    def _group_vulnerabilities_into_rules(self, vulnerabilities: Vulnerability) -> list:
        """Method for summarizing vulnerabilities and grouping into rules"""
        if len(vulnerabilities) <= 0:
            return {}, {}

        rules = []
        results = []
        for idx, vulnerability in enumerate(vulnerabilities):
            rule = {}
            rule["id"] = str(uuid.uuid4())
            rule["name"] = vulnerability.overview
            rule["shortDescription"] = {"text": vulnerability.overview}
            rule["fullDescription"] = {"text": vulnerability.vulnerability_type + "/" + vulnerability.recommendation}
            rules.append(rule)

            result = {"ruleId": "", "ruleIndex": -1, "level": "", "message": {"text": ""}, "locations": []}
            result["ruleId"] = rule["id"]
            result["ruleIndex"] = idx
            result["level"] = VulnerabilitySeverityEnum.normalise_name(vulnerability.severity).upper()
            result["message"] = {"text": vulnerability.overview}
            result["locations"].append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": py_.get(vulnerability.file_location, "path", "unknown")},
                        "region": {"startLine": py_.get(vulnerability.file_location, "line", "unknown")},
                    }
                }
            )
            results.append(result)
            return rules, results

    def _print_scan_report_warnings(self, scan_results_with_warnings: list):
        """Method for printing scan warnings"""

        if len(scan_results_with_warnings) <= 0:
            return

        click.echo(
            f"""
Warnings
================================="""
        )

        tool = {"driver": {}}
        for scan_result in scan_results_with_warnings:
            warnings = scan_result.warnings
            for warning in warnings:
                single_run = {"tool": {}, "artifacts": [], "results": [], "taxonomies": []}

                tool = {"driver": {}}
                tool["driver"]["name"] = py_.get(scan_result.run_details, "tool_name", "unknown")
                tool["driver"]["rules"] = []
                single_run["tool"] = tool
                single_run["artifacts"] = []
                single_run["results"] = []

                result = {"ruleId": "", "ruleIndex": -1, "level": "", "message": {"text": ""}, "locations": []}
                result["ruleId"] = str(uuid.uuid4())
                result["message"] = {"text": warning}
                single_run["results"].append(result)
                return single_run
