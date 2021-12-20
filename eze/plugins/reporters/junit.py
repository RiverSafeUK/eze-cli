"""JUnit Report class

Will output junit format file
https://llg.cubic.org/docs/junit/"""
from datetime import datetime

from pydash import py_

from eze import __version__
from eze.core.reporter import ReporterMeta
from eze.core.enums import Vulnerability
from eze.core.tool import ScanResult
from eze.utils.io import xescape, write_text
from eze.utils.log import log


class JunitReporter(ReporterMeta):
    """Python report class for echoing all output into a json file"""

    REPORTER_NAME: str = "junit"
    SHORT_DESCRIPTION: str = "junit output file reporter"
    INSTALL_HELP: str = """inbuilt"""
    MORE_INFO: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": "eze_junit_report.xml",
            "help_text": """report file location
By default set to eze_junit_report.xml""",
        }
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return __version__

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output"""
        xml_str = self._build_xml_str(scan_results)
        xml_location = write_text(self.config["REPORT_FILE"], xml_str)
        log(f"written junit report : {xml_location}")

    def _build_xml_str(self, scan_results: list) -> str:
        """build junit xml str
        see https://en.wikipedia.org/wiki/JUnit"""

        grand_totals = {"errors": 0, "failures": 0, "disabled": 0, "tests": 0, "duration_sec": 0}
        for scan_result in scan_results:
            failures = scan_result.summary["totals"]["total"]
            skipped = scan_result.summary["ignored"]["total"]
            token_success = 1
            grand_totals["disabled"] += skipped
            grand_totals["failures"] += failures
            grand_totals["tests"] += failures + skipped + token_success
            duration_sec = py_.get(scan_result.run_details, "duration_sec", "0")
            grand_totals["duration_sec"] += duration_sec

        xml_str = (
            f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuites disabled="{xescape(grand_totals["disabled"])}"
  errors="{xescape(grand_totals["errors"])}"
  failures="{xescape(grand_totals["failures"])}"
  name="eze report"
  tests="{xescape(grand_totals["tests"])}"
  time="{xescape(grand_totals["duration_sec"])}"
>"""
            + "\n"
        )

        for scan_result in scan_results:
            xml_str += self._create_test_suite(scan_result) + "\n"
        xml_str += "</testsuites>" + "\n"
        return xml_str

    def _create_test_suite(self, scan_result: ScanResult) -> str:
        """create junit test suite string"""
        my_date = datetime.now()
        tool_name = py_.get(scan_result.run_details, "tool_name", "unknown")
        run_type = (
            f"-{scan_result.run_details['run_type']}"
            if "run_type" in scan_result.run_details and scan_result.run_details["run_type"]
            else ""
        )
        scan_type = (
            f"{scan_result.run_details['scan_type']}-"
            if "scan_type" in scan_result.run_details and scan_result.run_details["scan_type"]
            else ""
        )
        errors = 0
        failures = scan_result.summary["totals"]["total"]
        skipped = scan_result.summary["ignored"]["total"]
        token_success = 1
        duration_sec = py_.get(scan_result.run_details, "duration_sec", "0")

        indent = "    "
        testsuite_str = (
            f"""{indent}<testsuite name="{xescape(scan_type)}{xescape(tool_name)}{xescape(run_type)}"
{indent}  time="{duration_sec:0.1f}"
{indent}  timestamp="{xescape(my_date.isoformat())}"
{indent}  disabled="{xescape(skipped)}"
{indent}  errors="{xescape(errors)}"
{indent}  failures="{xescape(failures)}"
{indent}  tests="{xescape(failures + skipped + token_success)}"
{indent}>"""
            + "\n"
        )

        # add one passing test, so jenkins doesn't auto fail suite for having no tests
        testsuite_str += (
            f"""{indent}{indent}<testcase name="{xescape(scan_type)}{xescape(tool_name)}{xescape(run_type)}-ran" classname="{xescape(tool_name)}{xescape(run_type)}"></testcase>"""
            + "\n"
        )

        if scan_result.warnings:
            warnings_str = ""
            for warning in scan_result.warnings:
                warnings_str += warning + "\n"
            testsuite_str += f"{indent}{indent}<system-err>{xescape(warnings_str)}</system-err>" + "\n"
        vulnerability: Vulnerability = None
        counter = 0
        for vulnerability in scan_result.vulnerabilities:
            counter += 1
            testsuite_str += self._create_test_case(vulnerability, str(counter), f"{indent}{indent}")

        testsuite_str += f"{indent}</testsuite>" + "\n"
        return testsuite_str

    def _create_test_case(self, obj, test_id: str, indent: str) -> str:
        """create junit test case string"""
        testcase_str = (
            f"""{indent}<testcase name="{xescape(obj.name + '-failure-' + test_id)}" classname="{xescape(obj.name)}">"""
            + "\n"
        )
        identifier_values = []
        for identifier_key in obj.identifiers:
            identifier_value = obj.identifiers[identifier_key]
            identifier_values.append(f"""{identifier_value}""")
        identifier_str = ":".join(identifier_values)

        if obj.is_ignored:
            testcase_str += f"""{indent}    <skipped message="ignored:{xescape(identifier_str)}{xescape(obj.overview)}{xescape(obj.recommendation)}"></skipped>"""
        else:
            testcase_str += (
                f"""{indent}    <failure message="{xescape(obj.overview)}"
{indent}      type="{xescape(identifier_str)}"
{indent}    >{xescape(obj.recommendation)}</failure>"""
                + "\n"
            )
        testcase_str += f"""{indent}</testcase>""" + "\n"
        return testcase_str
