"""Console reporter class implementation"""
import click
from pydash import py_

from eze import __version__
from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum
from eze.core.reporter import ReporterMeta
from eze.core.tool import ScanResult, Vulnerability
from eze.utils.scan_result import (
    vulnerabilities_short_summary,
    bom_short_summary,
    name_and_time_summary,
    get_bom_license,
)
from eze.utils.print import pretty_print_table


class ConsoleReporter(ReporterMeta):
    """Python report class for echoing all output into the console"""

    REPORTER_NAME: str = "console"
    SHORT_DESCRIPTION: str = "standard command line reporter"
    INSTALL_HELP: str = """inbuilt"""
    MORE_INFO: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    EZE_CONFIG: dict = {
        "PRINT_SUMMARY_ONLY": {
            "type": bool,
            "default": False,
            "help_text": """Whether or not to only print the summary (not bom or vulnerabilities)
defaults to false""",
        },
        "PRINT_IGNORED": {
            "type": bool,
            "default": False,
            "help_text": """Whether or not to print out ignored vulnerabilities
defaults to false""",
        },
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return __version__

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output"""
        click.echo("Eze report results:\n")
        scan_results_with_vulnerabilities = []
        scan_results_with_sboms = []
        scan_results_with_warnings = []
        scan_results_with_errors = []
        self.print_scan_summary_table(scan_results)

        if self.config["PRINT_SUMMARY_ONLY"]:
            return

        for scan_result in scan_results:
            if self._has_printable_vulnerabilities(scan_result):
                scan_results_with_vulnerabilities.append(scan_result)
            if scan_result.bom:
                scan_results_with_sboms.append(scan_result)
            if len(scan_result.warnings) > 0:
                scan_results_with_warnings.append(scan_result)
            if len(scan_result.fatal_errors) > 0:
                scan_results_with_errors.append(scan_result)

        self._print_scan_report_errors(scan_results_with_errors)
        self._print_scan_report_warnings(scan_results_with_warnings)
        self._print_scan_report_vulnerabilities(scan_results_with_vulnerabilities)
        self._print_scan_report_sbom(scan_results_with_sboms)

    def print_scan_summary_table(self, scan_results: list):
        """Print scan summary as table"""
        boms = []
        summaries = []
        for scan_result in scan_results:
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
            scan_type = (
                run_details["tool_type"] if "tool_type" in run_details and run_details["tool_type"] else "unknown"
            )
            duration_sec = py_.get(run_details, "duration_sec", "unknown")

            if scan_result.bom:
                boms.append(f"BILL OF MATERIALS: {tool_name}{run_type} (duration: {'{:.1f}s'.format(duration_sec)})")
                boms.append(f"    {bom_short_summary(scan_result)}")

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
                    entry["Ignored"] = "Error"
                    entry["Critical"] = "Error"
                    entry["High"] = "Error"
                    entry["Medium"] = "Error"
                    entry["Low"] = "Error"
                summaries.append(entry)
        pretty_print_table(summaries, False)
        if len(boms) > 0:
            print("\n".join(boms))

    def print_scan_summary_title(self, scan_result: ScanResult, prefix: str = "") -> str:
        """Title of scan summary title"""

        scan_summary = f"""{prefix}TOOL REPORT: {name_and_time_summary(scan_result, "")}\n"""

        # bom count if exists
        if scan_result.bom:
            scan_summary += bom_short_summary(scan_result, prefix + "    ")

        # if bom only scan, do not print vulnerability count
        if len(scan_result.vulnerabilities) > 0 or not scan_result.bom:
            scan_summary += vulnerabilities_short_summary(scan_result, prefix + "    ")
        click.echo(scan_summary)

    def _has_printable_vulnerabilities(self, scan_result: ScanResult) -> bool:
        """Method for taking scan vulnerabilities return True if anything to print"""
        if len(scan_result.vulnerabilities) <= 0:
            return False
        if not self.config["PRINT_IGNORED"] and scan_result.summary["totals"]["total"] == 0:
            return False
        return True

    def _print_scan_report_vulnerabilities(self, scan_results_with_vulnerabilities: list):
        """Method for taking scan vulnerabilities and printing them"""

        if len(scan_results_with_vulnerabilities) <= 0:
            return
        click.echo(
            """
Vulnerabilities
================================="""
        )
        for scan_result in scan_results_with_vulnerabilities:
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
            small_indent = "    "
            indent = "        "
            click.echo(
                f"""
{small_indent}[{tool_name}{run_type}] Vulnerabilities
{small_indent}================================="""
            )
            self.print_scan_summary_title(scan_result, "    ")
            vulnerability: Vulnerability = None
            for vulnerability in scan_result.vulnerabilities:
                if vulnerability.is_ignored:
                    # INFO: By Default ignore "ignored vulnerabilities"
                    if self.config["PRINT_IGNORED"]:
                        click.echo(f"""{indent}(ignored)""")
                    else:
                        continue

                severity = VulnerabilitySeverityEnum.normalise_name(vulnerability.severity).upper()
                vulnerability_type = VulnerabilityType.normalise_name(vulnerability.vulnerability_type).upper()
                first_line = f"""{indent}[{severity} {vulnerability_type}] : {vulnerability.name}"""
                if vulnerability.version:
                    first_line += f" ({vulnerability.version})"
                click.echo(first_line)
                click.echo(f"""{indent}overview: {vulnerability.overview}""")
                for identifier_key in vulnerability.identifiers:
                    identifier_value = vulnerability.identifiers[identifier_key]
                    click.echo(f"""{indent}{identifier_key}: {identifier_value}""")

                if vulnerability.recommendation:
                    click.echo(f"""{indent}recommendation: {vulnerability.recommendation}""")

                if vulnerability.file_location:
                    click.echo(
                        f"""{indent}file: {vulnerability.file_location.get('path')} (line {vulnerability.file_location.get('line')})"""
                    )
                click.echo("")

    def _print_scan_report_sbom(self, scan_results_with_sboms: list):
        """print scan sbom"""
        if len(scan_results_with_sboms) <= 0:
            return
        click.echo(
            """
Bill of Materials
================================="""
        )
        for scan_result in scan_results_with_sboms:
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
            click.echo(
                f"""
[{tool_name}{run_type}] SBOM
================================="""
            )
            sboms = []
            for component in scan_result.bom["components"]:
                licenses = component.get("licenses", [])

                license_txt = "unknown"
                # manual parsing for name and id
                if licenses and len(licenses) > 0:
                    license_texts = []
                    for license_obj in licenses:
                        license_text = get_bom_license(license_obj)
                        if license_text:
                            license_texts.append(license_text)
                    license_txt = ", ".join(license_texts)

                component_name = component["name"]
                component_group = component.get("group")
                if component_group:
                    component_name = f"{component_group}.{component_name}"

                sboms.append(
                    {
                        "type": component["type"],
                        "name": component_name,
                        "version": component["version"],
                        "license": license_txt,
                        "description": component.get("description", ""),
                    }
                )
            pretty_print_table(sboms)

    def _print_scan_report_warnings(self, scan_results_with_warnings: list):
        """print scan warnings"""
        if len(scan_results_with_warnings) <= 0:
            return

        click.echo(
            """
Warnings
================================="""
        )
        for scan_result in scan_results_with_warnings:
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
            small_indent = "    "
            indent = "        "
            click.echo(
                f"""
{small_indent}[{tool_name}{run_type}] Warnings
{small_indent}================================="""
            )
            for warning in scan_result.warnings:
                click.echo(f"""{indent}{warning}""")

    def _print_scan_report_errors(self, scan_results_with_errors: list):
        """print scan errors"""
        if len(scan_results_with_errors) <= 0:
            return

        click.echo(
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
            click.echo(
                f"""
{small_indent}[{tool_name}{run_type}] Errors
{small_indent}================================="""
            )
            for fatal_error in scan_result.fatal_errors:
                click.echo(f"""{indent}{fatal_error}""")
