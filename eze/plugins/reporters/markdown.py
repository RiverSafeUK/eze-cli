"""Markdown reporter class implementation"""
from pydash import py_

from eze import __version__
from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum, Vulnerability
from eze.core.reporter import ReporterMeta
from eze.core.tool import ScanResult
from eze.utils.io import write_text
from eze.utils.scan_result import (
    vulnerabilities_short_summary,
    bom_short_summary,
    name_and_time_summary,
)
from eze.utils.print import generate_markdown_table
from eze.utils.license import annotate_licenses, annotated_sbom_table


class MarkdownReporter(ReporterMeta):
    """Python report class for echoing output into a markdown report"""

    REPORTER_NAME: str = "markdown"
    SHORT_DESCRIPTION: str = "markdown output file formatter"
    INSTALL_HELP: str = """inbuilt"""
    MORE_INFO: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": "eze_report.md",
            "help_text": """report file location
By default set to eze_report.md""",
        },
    }

    report_lines = []

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return __version__

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output"""

        self.report_lines.append(
            """
# Eze Report Results
"""
        )
        scan_results_with_vulnerabilities = []
        scan_results_with_sboms = []
        scan_results_with_warnings = []
        scan_results_with_errors = []
        self.print_scan_summary_table(scan_results)

        for scan_result in scan_results:
            if self._has_printable_vulnerabilities(scan_result):
                scan_results_with_vulnerabilities.append(scan_result)
            if scan_result.sboms:
                scan_results_with_sboms.append(scan_result)
            if len(scan_result.warnings) > 0:
                scan_results_with_warnings.append(scan_result)
            if len(scan_result.fatal_errors) > 0:
                scan_results_with_errors.append(scan_result)

        self._print_scan_report_errors(scan_results_with_errors)
        self._print_scan_report_vulnerabilities(scan_results_with_vulnerabilities)
        self._print_scan_report_sbom(scan_results_with_sboms)
        self._print_scan_report_warnings(scan_results_with_warnings)

        report_str = ""
        for line in self.report_lines:
            report_str += line + "\n"
        file_location = write_text(self.config["REPORT_FILE"], report_str)
        print(f"Written markdown report : {file_location}")

    def print_scan_summary_table(self, scan_results: list):
        """Print scan summary as table"""
        sboms = []
        summaries = []
        for scan_result in scan_results:
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
            scan_type = (
                run_details["tool_type"] if "tool_type" in run_details and run_details["tool_type"] else "unknown"
            )
            duration_sec = py_.get(run_details, "duration_sec", "unknown")

            if scan_result.sboms:
                sboms.append(f"BILL OF MATERIALS: {tool_name}{run_type} (duration: {'{:.1f}s'.format(duration_sec)})")
                sboms.append(f"    {bom_short_summary(scan_result)}")

            entry = {
                "Name": tool_name + run_type,
                "Type": scan_type,
                "Critical": "-",
                "High": "-",
                "Medium": "-",
                "Low": "-",
                "Ignored": "-",
                "Warnings": str(len(scan_result.warnings) > 0) or len(scan_result.fatal_errors) > 0,
                "Time": "{:.1f}s".format(duration_sec),
            }

            if len(scan_result.vulnerabilities) > 0 or not scan_result.bom:
                entry["Ignored"] = str(scan_result.summary["ignored"]["total"])
                entry["Critical"] = str(scan_result.summary["totals"]["critical"])
                entry["High"] = str(scan_result.summary["totals"]["high"])
                entry["Medium"] = str(scan_result.summary["totals"]["medium"])
                entry["Low"] = str(scan_result.summary["totals"]["low"])
                if len(scan_result.fatal_errors) > 0:
                    entry["Ignored"] = 0
                    entry["Critical"] = 0
                    entry["High"] = 0
                    entry["Medium"] = 0
                    entry["Low"] = 0
                summaries.append(entry)

        critical = 0
        high = 0
        medium = 0
        low = 0

        for entry in summaries:
            critical += int(py_.get(entry, "Critical", 0))
            high += int(py_.get(entry, "High", 0))
            medium += int(py_.get(entry, "Medium", 0))
            low += int(py_.get(entry, "Low", 0))
            # warnings?
        self.report_lines.append(
            f"""
## Summary  ![tools](https://img.shields.io/static/v1?style=plastic&label=Tools&message={len(scan_results)}&color=blue)
---
"""
        )

        self.report_lines.append(
            f"""
![critical](https://img.shields.io/static/v1?style=plastic&label=critical&message={critical}&color=red)
![high](https://img.shields.io/static/v1?style=plastic&label=high&message={high}&color=orange)
![medium](https://img.shields.io/static/v1?style=plastic&label=medium&message={medium}&color=yellow)
![low](https://img.shields.io/static/v1?style=plastic&label=low&message={low}&color=lightgrey)
            """
        )

        git_branch = py_.get(run_details, "git_branch", "unknown")
        if git_branch != "unknown":
            self.report_lines.append(f"<b>Branch tested: </b>{run_details['git_branch']}\n")

        self.report_lines.append("<b>Tools executed: </b>\n")
        for tool in scan_results:
            run_details = py_.get(tool, "run_details", "unknown")
            self.report_lines.append(
                f"""* {py_.get(tool, "tool", "unknown")} ({run_details["tool_type"] if "tool_type" in run_details and run_details["tool_type"] else "unknown"})
            """
            )

    def print_scan_summary_title(self, scan_result: ScanResult, prefix: str = "") -> str:
        """Title of scan summary title"""

        scan_summary = f"""{prefix}TOOL REPORT: {name_and_time_summary(scan_result, "")}\n"""

        # bom count if exists
        if scan_result.bom:
            scan_summary += bom_short_summary(scan_result, prefix + "    ")

        # if bom only scan, do not print vulnerability count
        if len(scan_result.vulnerabilities) > 0 or not scan_result.bom:
            scan_summary += vulnerabilities_short_summary(scan_result, prefix + "    ")
        self.report_lines.append(scan_summary)

    def _has_printable_vulnerabilities(self, scan_result: ScanResult) -> bool:
        """Method for taking scan vulnerabilities return True if anything to print"""
        if len(scan_result.vulnerabilities) <= 0:
            return False
        if scan_result.summary["totals"]["total"] == 0:
            return False
        return True

    def _print_scan_report_vulnerabilities(self, scan_results_with_vulnerabilities: list):
        """Method for taking scan vulnerabilities and printing them"""

        if len(scan_results_with_vulnerabilities) <= 0:
            return
        self.report_lines.append(
            """
## Vulnerabilities
---
"""
        )
        for scan_result in scan_results_with_vulnerabilities:
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
            small_indent = "    "
            indent = "        "
            self.report_lines.append(
                f"""
{small_indent}[{tool_name}{run_type}] Vulnerabilities
{small_indent}================================="""
            )
            self.print_scan_summary_title(scan_result, "    ")
            vulnerability: Vulnerability = None
            for vulnerability in scan_result.vulnerabilities:
                severity = VulnerabilitySeverityEnum.normalise_name(vulnerability.severity).upper()
                vulnerability_type = VulnerabilityType.normalise_name(vulnerability.vulnerability_type).upper()
                first_line = f"""{indent}[{severity} {vulnerability_type}] : {vulnerability.name}"""
                if vulnerability.version:
                    first_line += f" ({vulnerability.version})"
                self.report_lines.append(first_line)
                self.report_lines.append(f"""{indent}overview: {vulnerability.overview}""")
                for identifier_key in vulnerability.identifiers:
                    identifier_value = vulnerability.identifiers[identifier_key]
                    self.report_lines.append(f"""{indent}{identifier_key}: {identifier_value}""")

                if vulnerability.recommendation:
                    endline = "\n"
                    self.report_lines.append(
                        f"""{indent}recommendation: {vulnerability.recommendation.replace(endline, f"{endline}{indent}")}"""
                    )

                if vulnerability.file_location:
                    self.report_lines.append(
                        f"""{indent}file: {vulnerability.file_location.get('path')} (line {vulnerability.file_location.get('line')})"""
                    )
                self.report_lines.append("")

    def _print_scan_report_sbom(self, scan_results_with_sboms: list):
        """print scan sbom"""
        if len(scan_results_with_sboms) <= 0:
            return
        self.report_lines.append(
            """
## Bill of Materials
---
"""
        )
        label = "components"

        counter = 0
        line_badge = len(self.report_lines)
        self.report_lines.append("")

        for scan_result in scan_results_with_sboms:
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
            for project_name in scan_result.sboms:
                cyclonedx_bom = scan_result.sboms[project_name]
                self.report_lines.append(
                    f"""
    ### [{tool_name}{run_type}] {project_name} SBOM
    ---"""
                )
                sboms = annotated_sbom_table(cyclonedx_bom)
                counter += len(sboms)

                self.report_lines.append("")

                # generating SBOM markdown adding to report
                markdown_sboms = generate_markdown_table(sboms)
                markdown_sboms_lines = markdown_sboms.split("\n")
                self.report_lines.extend(markdown_sboms_lines)

        self.report_lines[
            line_badge
        ] = f"![{label}](https://img.shields.io/static/v1?style=plastic&label={label}&message={counter}&color=blue)"

    def _print_scan_report_warnings(self, scan_results_with_warnings: list):
        """print scan warnings"""
        if len(scan_results_with_warnings) <= 0:
            return

        self.report_lines.append(
            """
## Warnings
---"""
        )
        for scan_result in scan_results_with_warnings:
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
            small_indent = "    "
            indent = "        "
            self.report_lines.append(
                f"""
{small_indent}[{tool_name}{run_type}] Warnings
{small_indent}================================="""
            )
            for warning in scan_result.warnings:

                endline = "\n"
                self.report_lines.append(f"""{small_indent}{warning.replace(endline, f"{endline}{small_indent}")}""")

    def _print_scan_report_errors(self, scan_results_with_errors: list):
        """print scan errors"""
        if len(scan_results_with_errors) <= 0:
            return

        self.report_lines.append(
            """
Errors
================================="""
        )
        for scan_result in scan_results_with_errors:
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
            small_indent = "    "
            indent = "        "
            self.report_lines.append(
                f"""
{small_indent}[{tool_name}{run_type}] Errors
{small_indent}================================="""
            )
            for fatal_error in scan_result.fatal_errors:
                self.report_lines.append(f"""{indent}{fatal_error}""")
