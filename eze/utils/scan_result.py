"""Utilities for cyclone dx SBOM"""
from pydash import py_

from eze.core.tool import ScanResult, ToolMeta
from eze.utils.license import get_bom_license, check_licenses


def convert_sbom_into_scan_result(tool: ToolMeta, cyclonedx_bom: dict, project: str = "project"):
    """convert sbom into scan_result"""
    [vulnerabilities, warnings] = check_licenses(
        cyclonedx_bom,
        tool.config["LICENSE_CHECK"],
        tool.config["LICENSE_ALLOWLIST"],
        tool.config["LICENSE_DENYLIST"],
        project,
    )
    return ScanResult(
        {
            "tool": tool.TOOL_NAME,
            # bom is deprecated will be removed soon
            "bom": cyclonedx_bom,
            "sboms": {project: cyclonedx_bom},
            "vulnerabilities": vulnerabilities,
            "warnings": warnings,
        }
    )


def convert_multi_sbom_into_scan_result(tool: ToolMeta, cyclonedx_boms: dict):
    """convert sbom into scan_result"""
    first_bom = None
    vulnerabilities_list: list = []
    warnings_list: list = []
    for project_name in cyclonedx_boms:
        cyclonedx_bom = cyclonedx_boms[project_name]
        first_bom = cyclonedx_bom

        [vulnerabilities, warnings] = check_licenses(
            cyclonedx_bom,
            tool.config["LICENSE_CHECK"],
            tool.config["LICENSE_ALLOWLIST"],
            tool.config["LICENSE_DENYLIST"],
            project_name,
        )
        vulnerabilities_list.extend(vulnerabilities)
        warnings_list.extend(warnings)

    return ScanResult(
        {
            "tool": tool.TOOL_NAME,
            # bom is deprecated will be removed soon
            "bom": first_bom,
            "sboms": cyclonedx_boms,
            "vulnerabilities": vulnerabilities_list,
            "warnings": warnings_list,
        }
    )


def name_and_time_summary(scan_result: ScanResult, indent: str = "    ") -> str:
    """convert scan_result into one line summary"""
    run_details = scan_result.run_details
    #
    tool_name = py_.get(run_details, "tool_name", "unknown")
    run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
    scan_type = f"[{run_details['scan_type']}] " if "scan_type" in run_details and run_details["scan_type"] else ""
    duration_sec = py_.get(run_details, "duration_sec", "unknown")
    return f"""{indent}{scan_type}{tool_name}{run_type} (scan duration: {duration_sec:0.1f} seconds)"""


def bom_short_summary(scan_result: ScanResult, indent: str = "    ", print_transitive: bool = False) -> str:
    """convert bom into one line summary"""
    if not has_sbom_data(scan_result):
        return ""
    if len(scan_result.fatal_errors) > 0:
        return "ERROR when creating SBOM"
    totals_txts = []
    for project_name in scan_result.sboms:
        cyclonedx_bom = scan_result.sboms[project_name]
        license_counts = {}
        component_count = len(cyclonedx_bom["components"])
        totals_txt = f"""{indent}{project_name} components: {component_count}"""
        if component_count > 0:
            totals_txt += " ("
            breakdowns = []
            for component in cyclonedx_bom["components"]:
                is_transitive = py_.get(component, "properties.transitive", False)
                if not print_transitive and is_transitive:
                    continue
                licenses = component.get("licenses", [])
                if len(licenses) == 0:
                    license_counts["unknown"] = license_counts.get("unknown", 0) + 1
                for license_dict in licenses:
                    license_name = get_bom_license(license_dict)
                    if license_name:
                        license_counts[license_name] = license_counts.get(license_name, 0) + 1
            for license_name in license_counts:
                license_count = license_counts[license_name]
                breakdowns.append(f"{license_name}:{license_count}")
            totals_txt += ", ".join(breakdowns)
            totals_txt += ")"
            totals_txts.append(totals_txt)
    return "\n".join(totals_txts) + "\n"


def vulnerabilities_short_summary(scan_result: ScanResult, indent: str = "    ") -> str:
    """convert bom into one line summary"""
    summary_totals = scan_result.summary["totals"]
    summary_ignored = scan_result.summary["ignored"]
    return (
        f"""{indent}{_get_scan_summary_totals(summary_totals, "total", scan_result.warnings)}
{indent}{_get_scan_summary_totals(summary_ignored, "ignored", scan_result.warnings)}"""
        + "\n"
    )


def _get_scan_summary_totals(summary_totals: dict, title: str, warnings: list) -> str:
    """get text summary of summary dict"""
    totals_txt = f"{title}: {summary_totals['total']} "
    if summary_totals["total"] > 0:
        totals_txt += "("
        breakdowns = []
        for key in ["critical", "high", "medium", "low", "none", "na"]:
            if summary_totals[key] > 0:
                breakdowns.append(f"{key}:{summary_totals[key]}")

        if len(warnings) > 0:
            breakdowns.append("warnings:true")

        totals_txt += ", ".join(breakdowns)
        totals_txt += ")"
    return totals_txt


def has_sbom_data(scan_result: ScanResult) -> bool:
    """if scanresult has sbom data"""
    return bool(scan_result.sboms and len(scan_result.sboms) > 0)


def has_vulnerability_data(scan_result: ScanResult) -> bool:
    """if scanresult has vulnerability or has no sbom data (meaning vulnerabilities are zero)"""
    return len(scan_result.vulnerabilities) > 0 or not has_sbom_data(scan_result)
