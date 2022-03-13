"""Print as markdown helpers
"""

from eze.core.enums import Vulnerability, VulnerabilitySeverityEnum, VulnerabilityType
from eze.core.tool import ScanResult
from eze.utils.io.print import generate_markdown_table, generate_markdown_list, generate_markdown_header
from eze.utils.scan_result import (
    bom_short_summary,
    name_and_time_summary,
    vulnerabilities_short_summary,
    has_vulnerability_data,
    has_sbom_data,
)
from pydash import py_
from eze.utils.license import annotated_sbom_table


def _print_errors_from_scan_results(scan_results: list) -> str:
    """print errors from scan_results"""

    str_buffer = []
    if len(scan_results) <= 0:
        return ""

    str_buffer.append(generate_markdown_header("Errors", 2))
    str_buffer.append("""---""")
    for scan_result in scan_results:
        run_details = scan_result.run_details
        tool_name = py_.get(run_details, "tool_name", "unknown")
        run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
        run_type_concat = ":" + run_type if run_type != "" else run_type

        str_buffer.append(generate_markdown_header(f"[{tool_name}{run_type_concat}] Errors", 3))
        for fatal_error in scan_result.fatal_errors:
            str_buffer.append(f"""{fatal_error}""")

    return "\n".join(str_buffer)


def _print_warnings_from_scan_results(scan_results: list) -> str:
    """print warnings from scan_results"""

    str_buffer = []
    if len(scan_results) <= 0:
        return ""

    str_buffer.append(generate_markdown_header("Warnings", 2))
    str_buffer.append("---")
    for scan_result in scan_results:
        run_details = scan_result.run_details
        tool_name = py_.get(run_details, "tool_name", "unknown")
        run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
        if len(scan_result.warnings) > 0:
            str_buffer.append(generate_markdown_header(f"[{tool_name}{run_type}] Warnings", 3))
            str_buffer.append(generate_markdown_list(scan_result.warnings))

    return "\n".join(str_buffer)


def _print_sboms_from_scan_results(scan_results: list, print_transitive: bool = False) -> str:
    """print scan sbom"""

    str_buffer = []
    if len(scan_results) <= 0:
        return ""
    str_buffer.append(generate_markdown_header("Bill of Materials", 2))
    str_buffer.append("""---""")

    str_buffer.append("")

    for scan_result in scan_results:
        run_details = scan_result.run_details
        tool_name = py_.get(run_details, "tool_name", "unknown")
        run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
        for project_name in scan_result.sboms:
            cyclonedx_bom = scan_result.sboms[project_name]
            sboms = annotated_sbom_table(cyclonedx_bom, print_transitive)

            str_buffer.append(generate_markdown_header(f"[{tool_name}{run_type}] {project_name} SBOM", 3))
            str_buffer.append(
                f"""
![components](https://img.shields.io/static/v1?style=plastic&label=components&message={len(sboms)}&color=blue)
"""
            )

            # generating SBOM markdown adding to report
            markdown_sboms = generate_markdown_table(sboms)
            markdown_sboms_lines = markdown_sboms.split("\n")
            str_buffer.extend(markdown_sboms_lines)
        str_buffer.append("\n")

    return "\n".join(str_buffer)


def _print_vulnerabilities_from_scan_results(scan_results_with_vulnerabilities: list) -> str:
    """Method for taking scan vulnerabilities and printing them"""

    str_buffer = []

    if len(scan_results_with_vulnerabilities) <= 0:
        return ""

    str_buffer.append(generate_markdown_header("Vulnerabilities", 2))
    str_buffer.append("""---""")
    for scan_result in scan_results_with_vulnerabilities:
        run_details = scan_result.run_details
        tool_name = py_.get(run_details, "tool_name", "unknown")
        run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""

        str_buffer.append(generate_markdown_header(f"[{tool_name}{run_type}] Vulnerabilities", 3))
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
            str_buffer.append(vulnerability_str)
            str_buffer.append("")

    return "\n".join(str_buffer)


def _print_scan_summary_table(scan_results: list, print_transitive: bool = False):
    """Print scan summary as table"""

    str_buffer = []
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
            sboms.append(f"{bom_short_summary(scan_result, print_transitive)}")

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

        if has_vulnerability_data(scan_result):
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

    str_buffer.append(
        generate_markdown_header(
            f"Summary  ![tools](https://img.shields.io/static/v1?style=plastic&label=Tools&message={len(scan_results)}&color=blue)",
            2,
        )
    )
    str_buffer.append(
        f"""
---
"""
    )

    str_buffer.append(
        f"""
![critical](https://img.shields.io/static/v1?style=plastic&label=critical&message={critical}&color=red)
![high](https://img.shields.io/static/v1?style=plastic&label=high&message={high}&color=orange)
![medium](https://img.shields.io/static/v1?style=plastic&label=medium&message={medium}&color=yellow)
![low](https://img.shields.io/static/v1?style=plastic&label=low&message={low}&color=lightgrey)


"""
    )

    git_branch = "unknown" if len(scan_results) == 0 else py_.get(scan_results[0].run_details, "git_branch", "unknown")
    if git_branch != "unknown":
        str_buffer.append(f"<b>Branch tested:</b>&nbsp;{git_branch}")

    str_buffer.append(f"<b>Tools executed:</b>&nbsp;{len(scan_results)}")
    str_buffer.append("\n")
    tool_names = []
    for tool in scan_results:
        run_details = py_.get(tool, "run_details", "unknown")
        name = py_.get(tool, "tool", "unknown")
        type = run_details["tool_type"] if "tool_type" in run_details and run_details["tool_type"] else "unknown"
        tool_names.append(f"{name} ({type})")
    str_buffer.append(generate_markdown_list(tool_names))
    return "\n".join(str_buffer)


def _print_scan_summary_title(scan_result: ScanResult, prefix: str = "") -> str:
    """Title of scan summary title"""

    scan_summary = f"""{prefix}TOOL REPORT: {name_and_time_summary(scan_result, "")}\n"""

    # bom count if exists
    if has_sbom_data(scan_result):
        scan_summary += bom_short_summary(scan_result, prefix + "    ")

    # if bom only scan, do not print vulnerability count
    if has_vulnerability_data(scan_result):
        scan_summary += vulnerabilities_short_summary(scan_result, prefix + "    ")

    return scan_summary


def scan_results_as_markdown(scan_results: list, print_transitive: bool = False):
    """Method for taking scans and turning then into report output"""

    str_buffer = []
    scan_results_with_vulnerabilities = []
    scan_results_with_sboms = []
    scan_results_with_warnings = []
    scan_results_with_errors = []
    str_buffer.append(generate_markdown_header("Eze Report Results", 1))
    str_buffer.append(_print_scan_summary_table(scan_results, print_transitive))

    for scan_result in scan_results:
        if _has_printable_vulnerabilities(scan_result):
            scan_results_with_vulnerabilities.append(scan_result)
        if scan_result.sboms:
            scan_results_with_sboms.append(scan_result)
        if len(scan_result.warnings) > 0:
            scan_results_with_warnings.append(scan_result)
        if len(scan_result.fatal_errors) > 0:
            scan_results_with_errors.append(scan_result)

    str_buffer.append(_print_errors_from_scan_results(scan_results_with_errors))
    str_buffer.append(_print_vulnerabilities_from_scan_results(scan_results_with_vulnerabilities))
    str_buffer.append(_print_sboms_from_scan_results(scan_results_with_sboms, print_transitive))
    str_buffer.append(_print_warnings_from_scan_results(scan_results_with_warnings))

    return "\n".join(str_buffer)


def _has_printable_vulnerabilities(scan_result: ScanResult) -> bool:
    """Method for taking scan vulnerabilities return True if anything to print"""
    if len(scan_result.vulnerabilities) <= 0:
        return False
    if scan_result.summary["totals"]["total"] == 0:
        return False
    return True
