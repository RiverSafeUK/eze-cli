"""Print as markdown helpers
"""

from textwrap import dedent
from eze.core.enums import Vulnerability, VulnerabilitySeverityEnum, VulnerabilityType
from eze.core.tool import ScanResult
from eze.utils.print import generate_markdown_table
from eze.utils.scan_result import bom_short_summary, name_and_time_summary, vulnerabilities_short_summary
from pydash import py_
from eze.utils.license import annotated_sbom_table


def _print_errors_from_scan_results(scan_results: list) -> str:
    """print errors from scan_results"""

    str_list = []
    if len(scan_results) <= 0:
        return ""

    str_list.append(
        """
## Errors
---
"""
    )
    for scan_result in scan_results:
        run_details = scan_result.run_details
        tool_name = py_.get(run_details, "tool_name", "unknown")
        run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
        run_type_concat = ":" + run_type if run_type != "" else run_type
        str_list.append(
            f"""
### [{tool_name}{run_type_concat}] Errors"""
        )
        for fatal_error in scan_result.fatal_errors:
            str_list.append(f"""{fatal_error}""")

    return "\n".join(str_list)


def _print_warnings_from_scan_results(scan_results: list) -> str:
    """print warnings from scan_results"""

    str_list = []
    if len(scan_results) <= 0:
        return ""

    str_list.append(
        """
## Warnings
---
"""
    )
    for scan_result in scan_results:
        run_details = scan_result.run_details
        tool_name = py_.get(run_details, "tool_name", "unknown")
        run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
        str_list.append(
            f"""
### [{tool_name}{run_type}] Warnings"""
        )
        for warning in scan_result.warnings:
            endline = "\n"
            str_list.append(f"""{warning.replace(endline, f"{endline}")}""")

    return endline.join(str_list)


def _print_sboms_from_scan_results(scan_results: list) -> str:
    """print scan sbom"""

    str_list = []
    if len(scan_results) <= 0:
        return ""
    str_list.append(
        """
## Bill of Materials
---
"""
    )

    str_list.append("")

    for scan_result in scan_results:
        run_details = scan_result.run_details
        tool_name = py_.get(run_details, "tool_name", "unknown")
        run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
        for project_name in scan_result.sboms:
            cyclonedx_bom = scan_result.sboms[project_name]
            sboms = annotated_sbom_table(cyclonedx_bom)

            str_list.append(
                f"""
### [{tool_name}{run_type}] {project_name} SBOM
![components](https://img.shields.io/static/v1?style=plastic&label=components&message={len(sboms)}&color=blue)
"""
            )

            # generating SBOM markdown adding to report
            markdown_sboms = generate_markdown_table(sboms)
            markdown_sboms_lines = markdown_sboms.split("\n")
            str_list.extend(markdown_sboms_lines)
        str_list.append("\n")

    return "\n".join(str_list)


def _print_vulnerabilities_from_scan_results(scan_results_with_vulnerabilities: list) -> str:
    """Method for taking scan vulnerabilities and printing them"""

    str_list = []

    if len(scan_results_with_vulnerabilities) <= 0:
        return ""

    str_list.append(
        """
## Vulnerabilities
---
"""
    )
    for scan_result in scan_results_with_vulnerabilities:
        run_details = scan_result.run_details
        tool_name = py_.get(run_details, "tool_name", "unknown")
        run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
        str_list.append(
            f"""
### [{tool_name}{run_type}] Vulnerabilities
"""
        )
        _print_scan_summary_title(scan_result, "    ")
        vulnerability: Vulnerability = None
        for vulnerability in scan_result.vulnerabilities:
            severity = VulnerabilitySeverityEnum.normalise_name(vulnerability.severity).upper()
            vulnerability_type = VulnerabilityType.normalise_name(vulnerability.vulnerability_type).upper()
            first_line = f"""[{severity} {vulnerability_type}] : {vulnerability.name}"""
            if vulnerability.version:
                first_line += f" ({vulnerability.version})"
            vulnerability_identifier = ""
            for identifier_key in vulnerability.identifiers:
                identifier_value = vulnerability.identifiers[identifier_key]
                vulnerability_identifier = f"{identifier_key}: {identifier_value}"

            recommendation_str = "none"
            if vulnerability.recommendation:
                recommendation_str = f"""{vulnerability.recommendation.strip()}"""

            location_block = ""
            if vulnerability.file_location:
                location_block = f"""
**file**: {vulnerability.file_location.get('path')} (line {vulnerability.file_location.get('line')})
"""

            vulnerability_str = f"""
**{first_line}**


**overview**: {vulnerability.overview}


{vulnerability_identifier}

**recommendation**: {recommendation_str}


{location_block}
"""
            str_list.append(vulnerability_str)
            str_list.append("")

    return "\n".join(str_list)


def _print_scan_summary_table(scan_results: list):
    """Print scan summary as table"""

    str_list = []
    sboms = []
    summaries = []

    for scan_result in scan_results:
        run_details = scan_result.run_details
        tool_name = py_.get(run_details, "tool_name", "unknown")
        run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
        scan_type = run_details["tool_type"] if "tool_type" in run_details and run_details["tool_type"] else "unknown"
        duration_sec = py_.get(run_details, "duration_sec", 0)

        if scan_result.sboms:
            sboms.append(f"BILL OF MATERIALS: {tool_name}{run_type} (duration: {'{:.1f}s'.format(duration_sec)})")
            sboms.append(f"{bom_short_summary(scan_result)}")

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

    str_list.append(
        f"""
## Summary  ![tools](https://img.shields.io/static/v1?style=plastic&label=Tools&message={len(scan_results)}&color=blue)
---
"""
    )

    str_list.append(
        f"""
![critical](https://img.shields.io/static/v1?style=plastic&label=critical&message={critical}&color=red)
![high](https://img.shields.io/static/v1?style=plastic&label=high&message={high}&color=orange)
![medium](https://img.shields.io/static/v1?style=plastic&label=medium&message={medium}&color=yellow)
![low](https://img.shields.io/static/v1?style=plastic&label=low&message={low}&color=lightgrey)


"""
    )

    git_branch = "unknown" if len(scan_results) == 0 else py_.get(scan_results[0].run_details, "git_branch", "unknown")
    if git_branch != "unknown":
        str_list.append(f"<b>Branch tested: </b>{git_branch}")

    str_list.append(f"<b>Tools executed: {len(scan_results)}</b>")
    for tool in scan_results:
        run_details = py_.get(tool, "run_details", "unknown")
        str_list.append(
            f"""* {py_.get(tool, "tool", "unknown")} ({run_details["tool_type"] if "tool_type" in run_details and run_details["tool_type"] else "unknown"})
"""
        )

    return "\n".join(str_list)


def _print_scan_summary_title(scan_result: ScanResult, prefix: str = "") -> str:
    """Title of scan summary title"""

    scan_summary = f"""{prefix}TOOL REPORT: {name_and_time_summary(scan_result, "")}\n"""

    # bom count if exists
    if scan_result.bom:
        scan_summary += bom_short_summary(scan_result, prefix + "    ")

    # if bom only scan, do not print vulnerability count
    if len(scan_result.vulnerabilities) > 0 or not scan_result.bom:
        scan_summary += vulnerabilities_short_summary(scan_result, prefix + "    ")

    return scan_summary


def print_scan_results_as_markdown(scan_results: list):
    """Method for taking scans and turning then into report output"""

    report_lines = []
    report_lines.append(
        """
# Eze Report Results
"""
    )
    scan_results_with_vulnerabilities = []
    scan_results_with_sboms = []
    scan_results_with_warnings = []
    scan_results_with_errors = []
    report_lines.append(_print_scan_summary_table(scan_results))

    for scan_result in scan_results:
        if _has_printable_vulnerabilities(scan_result):
            scan_results_with_vulnerabilities.append(scan_result)
        if scan_result.sboms:
            scan_results_with_sboms.append(scan_result)
        if len(scan_result.warnings) > 0:
            scan_results_with_warnings.append(scan_result)
        if len(scan_result.fatal_errors) > 0:
            scan_results_with_errors.append(scan_result)

    report_lines.append(_print_errors_from_scan_results(scan_results_with_errors))
    report_lines.append(_print_vulnerabilities_from_scan_results(scan_results_with_vulnerabilities))
    report_lines.append(_print_sboms_from_scan_results(scan_results_with_sboms))
    report_lines.append(_print_warnings_from_scan_results(scan_results_with_warnings))

    return "\n".join(report_lines)


def _has_printable_vulnerabilities(scan_result: ScanResult) -> bool:
    """Method for taking scan vulnerabilities return True if anything to print"""
    if len(scan_result.vulnerabilities) <= 0:
        return False
    if scan_result.summary["totals"]["total"] == 0:
        return False
    return True
