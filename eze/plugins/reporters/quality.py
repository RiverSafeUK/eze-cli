"""Quality reporter class implementation"""
from eze import __version__
from eze.core.enums import VulnerabilitySeverityEnum
from eze.core.reporter import ReporterMeta
from eze.utils.io import exit_app


class QualityReporter(ReporterMeta):
    """Python report class for echoing all output into the console"""

    REPORTER_NAME: str = "quality"
    SHORT_DESCRIPTION: str = "quality gate check reporter"
    INSTALL_HELP: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    MORE_INFO: str = """Note: this reporter is used to "threshold" the results, and throw a Application error
when a said threshold is exceeded (aka ala unit test suite)

This reporter is extremely versatile and designed to allow developers to set custom
threshold to match their environment needs

#
# Use case 1
# =====================
# Will exit when total number of vulnerabilities in all tools over VULNERABILITY_SEVERITY_THRESHOLD exceeds VULNERABILITY_COUNT_THRESHOLD

# [Optional] defaults to 0
VULNERABILITY_COUNT_THRESHOLD = 0

# [Optional] defaults to "medium"
VULNERABILITY_SEVERITY_THRESHOLD = "xxx"

#
# Use case 2
# =====================
# Set Explicit limits for each type of vulnerability

# [Optional] Will when errors of type over limit, not set by default
VULNERABILITY_CRITICAL_SEVERITY_LIMIT = xxx
VULNERABILITY_HIGH_SEVERITY_LIMIT = xxx
VULNERABILITY_MEDIUM_SEVERITY_LIMIT = xxx
VULNERABILITY_LOW_SEVERITY_LIMIT = xxx
VULNERABILITY_NONE_SEVERITY_LIMIT = xxx
VULNERABILITY_NA_SEVERITY_LIMIT = xxx
"""
    EZE_CONFIG: dict = {
        "VULNERABILITY_COUNT_THRESHOLD": {
            "type": int,
            "default": 0,
            "help_text": """Eze exit when total number of vulnerabilities in all tools
of severity exceeding VULNERABILITY_SEVERITY_THRESHOLD exceeds VULNERABILITY_COUNT_THRESHOLD""",
        },
        "VULNERABILITY_SEVERITY_THRESHOLD": {
            "type": str,
            "default": VulnerabilitySeverityEnum.medium.name,
            "help_text": """Eze exit when total number of vulnerabilities in all tools
of severity exceeding VULNERABILITY_SEVERITY_THRESHOLD exceeds VULNERABILITY_COUNT_THRESHOLD""",
        },
        #
        "VULNERABILITY_CRITICAL_SEVERITY_LIMIT": {
            "type": int,
            "help_text": """Eze exit when total number of vulnerabilities in all tools
of severity CRITICAL exceeds VULNERABILITY_CRITICAL_SEVERITY_LIMIT""",
        },
        "VULNERABILITY_HIGH_SEVERITY_LIMIT": {
            "type": int,
            "help_text": """Eze exit when total number of vulnerabilities in all tools
of severity HIGH exceeds VULNERABILITY_HIGH_SEVERITY_LIMIT""",
        },
        "VULNERABILITY_MEDIUM_SEVERITY_LIMIT": {
            "type": int,
            "help_text": """Eze exit when total number of vulnerabilities in all tools
of severity MEDIUM exceeds VULNERABILITY_MEDIUM_SEVERITY_LIMIT""",
        },
        "VULNERABILITY_LOW_SEVERITY_LIMIT": {
            "type": int,
            "help_text": """Eze exit when total number of vulnerabilities in all tools
of severity LOW exceeds VULNERABILITY_LOW_SEVERITY_LIMIT""",
        },
        "VULNERABILITY_NONE_SEVERITY_LIMIT": {
            "type": int,
            "help_text": """Eze exit when total number of vulnerabilities in all tools
of severity NONE exceeds VULNERABILITY_NONE_SEVERITY_LIMIT""",
        },
        "VULNERABILITY_NA_SEVERITY_LIMIT": {
            "type": int,
            "help_text": """Eze exit when total number of vulnerabilities in all tools
of severity NA exceeds VULNERABILITY_NA_SEVERITY_LIMIT""",
        },
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return __version__

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output"""

        # Use case 1
        # Will exit when total number of vulnerabilities in all tools over VULNERABILITY_SEVERITY_THRESHOLD exceeds VULNERABILITY_COUNT_THRESHOLD
        grand_totals = self._calc_grand_totals(scan_results)
        failures = self._count_failures(grand_totals)
        threshold_count = self.config["VULNERABILITY_COUNT_THRESHOLD"]
        threshold_severity = self.config["VULNERABILITY_SEVERITY_THRESHOLD"]
        if failures > threshold_count:
            self.fail_report(
                f"{failures} {threshold_severity}+ vulnerabilities exceeded threshold {threshold_count} {threshold_severity}+"
            )
            return

        # Use case 2
        # Set Explicit limits for each type of vulnerability
        for key in ["critical", "high", "medium", "low", "none", "na"]:
            upper_key = key.upper()
            key_failures = grand_totals[key]
            key_threshold = self.config[f"VULNERABILITY_{upper_key}_SEVERITY_LIMIT"]
            if key_threshold is not None and key_failures > key_threshold:
                self.fail_report(f"{key_failures} {key} vulnerabilities exceeded {key} threshold of {key_threshold}")

    def _calc_grand_totals(self, scan_results: list):
        """count the number of failures above threshold"""
        grand_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "na": 0}
        for scan_result in scan_results:
            for key in ["critical", "high", "medium", "low", "none", "na"]:
                grand_totals[key] += scan_result.summary["totals"][key]

        return grand_totals

    def _count_failures(self, grand_totals: dict):
        """count the number of failures above threshold"""
        total_failures = 0
        threshold_severity = self.config["VULNERABILITY_SEVERITY_THRESHOLD"]
        threshold_severity_int = VulnerabilitySeverityEnum[threshold_severity].value
        for key in ["critical", "high", "medium", "low", "none", "na"]:
            if VulnerabilitySeverityEnum[key].value <= threshold_severity_int:
                total_failures += grand_totals[key]
        return total_failures

    def fail_report(self, error_message: str):
        """call the failure report"""
        if error_message:
            exit_app(f"Quality Gate Failed: {error_message}")

    def _parse_config(self, config: dict) -> dict:
        """take raw config dict and normalise values"""
        parsed_config = super()._parse_config(config)

        # ADDITION PARSING: VULNERABILITY_SEVERITY_THRESHOLD
        # if invalid value, default to medium
        if not hasattr(VulnerabilitySeverityEnum, parsed_config["VULNERABILITY_SEVERITY_THRESHOLD"]):
            print(
                f'ERROR: invalid VULNERABILITY_SEVERITY_THRESHOLD:{parsed_config["VULNERABILITY_SEVERITY_THRESHOLD"]}, defaulting to {VulnerabilitySeverityEnum.medium.name}'
            )
            parsed_config["VULNERABILITY_SEVERITY_THRESHOLD"] = VulnerabilitySeverityEnum.medium.name

        return parsed_config
