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
)
from eze.utils.license import annotated_sbom_table
from eze.utils.log import log


class HtmlReporter(ReporterMeta):
    """Python report class for echoing output into a markdown report"""

    REPORTER_NAME: str = "html"
    SHORT_DESCRIPTION: str = "html output file formatter"
    INSTALL_HELP: str = """inbuilt"""
    MORE_INFO: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": ".eze/eze_report.html",
            "help_text": """report file location
By default set to eze_report.html""",
        },
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return __version__

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output"""

        html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <title>Eze Scanning report</title>
                <link 
                    href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" 
                    rel="stylesheet" 
                    integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" 
                    crossorigin="anonymous">
            </head>

            <body>
                <div class="container">
                    <h1> Eze Report Results </h1>
                    {self._print_scan_summary_table(scan_results)}
                    {self._print_errors_for_scan_results(scan_results)}
                    {self._print_vulnerabilities_for_scan_results(scan_results)}
                    {self._print_sbom_for_scan_results(scan_results)}
                    {self._print_warnings_for_scan_results(scan_results)}
                </div>
            </body>

            </html>
            """

        file_location = write_text(self.config["REPORT_FILE"], html)
        log(f"Written html report : {file_location}")

    def _print_scan_summary_table(self, scan_results: list) -> str:
        """Print scan summary as table"""
        sboms = []
        summaries = []
        summaries_str = ""

        for scan_result in scan_results:
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
            scan_type = py_.get(run_details, "tool_type", "unknown")
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

        git_branch = py_.get(run_details, "git_branch", "unknown")
        git_branch_str = ""
        if git_branch != "unknown":
            git_branch_str = f"<p><b>Branch tested: </b>{run_details['git_branch']}</p>"

        tools_str = ""
        for tool in scan_results:
            run_details = py_.get(tool, "run_details", "unknown")
            tool_name = py_.get(run_details, "tool_name", "unknown")
            tool_type = py_.get(run_details, "tool_type", "")
            if tool_type:
                tool_type = f"({tool_type})"
            tools_str += f"<li>{tool_name} {tool_type}</li>"

        summaries_str = f"""
                        <br>
                        <h2>Summary  <img src=https://img.shields.io/static/v1?style=plastic&label=Tools&message={len(scan_results)}&color=blue /></h2>
                        <hr />

                            <img src=https://img.shields.io/static/v1?style=plastic&label=critical&message={critical}&color=red />
                            <img src=https://img.shields.io/static/v1?style=plastic&label=high&message={high}&color=orange />
                            <img src=https://img.shields.io/static/v1?style=plastic&label=medium&message={medium}&color=yellow />
                            <img src=https://img.shields.io/static/v1?style=plastic&label=low&message={low}&color=lightgrey />
                        <br>
                        {git_branch_str}
                        <br>
                        <b>Tools executed: </b>
                        <br>
                        <ul>
                            {tools_str}
                        </ul>
            """

        return summaries_str

    def _print_vulnerabilities_for_scan_results(self, scan_results_with_vulnerabilities: list) -> str:
        """Method for printing all scan vulnerabilities and printing them"""

        def _has_printable_vulnerabilities(scan_result: ScanResult) -> bool:
            """Method for taking scan vulnerabilities return True if anything to print"""
            if len(scan_result.vulnerabilities) <= 0:
                return False
            if scan_result.summary["totals"]["total"] == 0:
                return False
            return True

        if len(scan_results_with_vulnerabilities) <= 0:
            return

        vulnerabilities_str = f"""
            <br>
            <h2>Vulnerabilities</h2>
            <hr />
            """

        for scan_result in scan_results_with_vulnerabilities:
            if _has_printable_vulnerabilities(scan_result):
                vulnerabilities_str += self._print_vulnerabilities_for_scan_result(scan_result)
        return vulnerabilities_str

    def _print_vulnerabilities_for_scan_result(self, scan_result: ScanResult) -> str:
        """print all the vulnerabilities found for each tool"""
        all_tables = [
            self._print_vulnerability_as_table(vulnerability, idx + 1)
            for idx, vulnerability in enumerate(scan_result.vulnerabilities)
        ]
        run_details = scan_result.run_details
        tool_name = py_.get(run_details, "tool_name", "unknown")
        duration = py_.get(run_details, "duration_sec", "unknown")
        duration = "{:.1f}s".format(duration)
        new_line = "\n"

        return f"""
            <br>
            <h3> [{tool_name}] Vulnerabilities</h3>
            <h4> TOOL REPORT: {tool_name} (scan duration: {duration})</h4>

            <p>({self.print_vulnerabilities_summary(scan_result, "    ")})</p>

            { new_line.join(all_tables)}
            """

    def _print_vulnerability_as_table(self, vulnerability, index) -> str:
        """print each vulnerability as a table"""
        severity = VulnerabilitySeverityEnum.normalise_name(vulnerability.severity).upper()
        vulnerability_type = VulnerabilityType.normalise_name(vulnerability.vulnerability_type).upper()
        version = "" if not vulnerability.version else f" ({vulnerability.version})"

        identifier = "-"
        for identifier_key in vulnerability.identifiers:
            identifier_value = vulnerability.identifiers[identifier_key]
            identifier = f"""{identifier_key}: {identifier_value}"""

        vuln_table_str = f"""<table class="table table-bordered">
            <tr>
                <th colspan=2 class="text-break">
                   {index}. [{severity} {vulnerability_type}] : {vulnerability.name} {version}
                </th>
            </tr>
            <tr>
                <th>identifiers</td>
                <td>{identifier}</td>
            </tr>
            <tr>
                <th>overview</th>
                <td class="text-break">
                    {vulnerability.overview}
                </td>
            </tr>
            <tr>
                <th>recommendation</th>
                <td class="text-break">
                    {self._escape_text(vulnerability.recommendation)}
                </td>
            </tr>
            <tr>
                <th>file</th>
                <td>
                    {py_.get(vulnerability.file_location, "path", "unknown")} (line {py_.get(vulnerability.file_location, "line", "unknown")})
                </td>
            </tr>
        </table>
"""
        return vuln_table_str

    def print_vulnerabilities_summary(self, scan_result: ScanResult, prefix: str = "") -> str:
        """Title of scan summary title"""

        scan_summary = ""

        if len(scan_result.vulnerabilities) > 0 or not scan_result.bom:
            scan_summary += vulnerabilities_short_summary(scan_result, prefix + "    ")
        return scan_summary

    def _print_sbom_for_scan_results(self, scan_results_with_sboms: list):
        """print scan sbom"""

        counter = 0
        sboms_str = ""
        for scan_result in scan_results_with_sboms:
            if not scan_result.sboms:
                continue

            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = py_.get(run_details, "run_type", "")

            for project_name in scan_result.sboms:
                counter += 1
                sboms_str += self._print_sbom_as_html(
                    tool_name, run_type, project_name, scan_result.sboms[project_name]
                )

        if counter == 0:
            return ""

        return f"""
                <br>
                <h2>Bill of Materials</h2>
                <hr />
                    <img src=https://img.shields.io/static/v1?style=plastic&label=boms&message={counter}&color=blue/>
                <br>
                {sboms_str}
            """

    def _print_sbom_as_html(self, tool_name, run_type, project_name, bom):
        sbom_str = ""
        sboms = annotated_sbom_table(bom)
        if run_type:
            run_type = ":" + run_type
        sbom_str += f"""
        <h3>[{tool_name}{run_type}] {project_name} SBOM</h3>
        <img src=https://img.shields.io/static/v1?style=plastic&label=components&message={len(sboms)}&color=blue/>
        <br> 
        """
        sbom_str += f"""
                    <table class="table table-bordered">
                    <thead>
                        <tr>
                            <th>type</th>
                            <th>name</th>
                            <th>version</th>
                            <th>license</th>
                            <th>license type</th>
                            <th>description</th>
                        </tr>
                    </thead>
                    <tbody>
            """

        # generating SBOM markdown adding to report

        for sbom in sboms:
            sbom_str += f"""
                <tr>
                    <td>{sbom["type"]}</td>
                    <td>{sbom["name"]}</td>
                    <td>{sbom["version"]}</td>
                    <td>{sbom["license"]}</td>
                    <td>{sbom["license type"]}</td>
                    <td>{sbom["description"]}</td>
                </tr>
                """

        sbom_str += """</tbody>
                       </table>
            """
        return sbom_str

    def _print_warnings_for_scan_results(self, scan_results: list) -> str:
        """print scan warnings"""

        tools_str = ""
        warning_count = 0
        for scan_result in scan_results:
            if len(scan_result.warnings) == 0:
                continue
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""

            tools_str += f"""<h3>{tool_name}{run_type}</h3>"""
            for warning in scan_result.warnings:
                tools_str += f"""
                    <div class="alert alert-warning" role="alert">
                        {self._escape_text(warning)}
                    </div>
                    """
                warning_count += 1

        if warning_count == 0:
            tools_str = """
            <div class="alert alert-light" role="alert">
                No warnings
            </div>
            """

        return f"""
            <br>
            <h2>Warnings</h2>
            <hr />
            {tools_str}
            """

    def _print_errors_for_scan_results(self, scan_results: list):
        """print scan errors"""

        tools_str = ""
        error_count = 0
        for scan_result in scan_results:
            if len(scan_result.fatal_errors) == 0:
                continue
            run_details = scan_result.run_details
            tool_name = py_.get(run_details, "tool_name", "unknown")
            run_type = f":{run_details['run_type']}" if "run_type" in run_details and run_details["run_type"] else ""
            tools_str += f"""<h3>{tool_name}{run_type}</h3>"""

            for fatal_error in scan_result.fatal_errors:
                tools_str += f"""
                    <div class="alert alert-danger" role="alert">
                        {self._escape_text(fatal_error)}
                    </div>
                """
                error_count += 1

        if error_count == 0:
            tools_str = """
            <div class="alert alert-light" role="alert">
                No errors
            </div>
            """

        return f"""
                <br>
                <h2>Errors</h2>
                <hr />
                {tools_str}
            """

    def _escape_text(self, txt):
        return txt.replace("<", "&lt;").replace(">", "&gt;")
