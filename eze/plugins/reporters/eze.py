"""Eze reporter class implementation"""
import os
import urllib.request

from eze import __version__
from eze.core.reporter import ReporterMeta
from eze.utils.git import get_active_branch_name, get_active_branch_uri
from eze.utils.io import pretty_print_json
from eze.utils.error import EzeConfigError, EzeNetworkingError, EzeError
from eze.utils.http import request_json
from eze.utils.log import log, log_debug, log_error


class EzeReporter(ReporterMeta):
    """Python report class for sending scan reports to eze management console"""

    REPORTER_NAME: str = "eze"
    SHORT_DESCRIPTION: str = "eze management console reporter"
    INSTALL_HELP: str = """inbuilt"""
    MORE_INFO: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    EZE_CONFIG: dict = {
        "APIKEY": {
            "type": str,
            "required": False,
            "default": os.environ.get("EZE_APIKEY", ""),
            "default_help_value": "ENVIRONMENT VARIABLE <EZE_APIKEY>",
            "help_text": """EZE_APIKEY required to send to server
WARNING: not stored in version control .ezerc.toml
it can also be specified as the environment variable EZE_APIKEY
get EZE_APIKEY from eze console profile page""",
        },
        "CONSOLE_ENDPOINT": {
            "type": str,
            "required": True,
            "default": os.environ.get("EZE_CONSOLE_ENDPOINT", ""),
            "default_help_value": "ENVIRONMENT VARIABLE <EZE_CONSOLE_ENDPOINT>",
            "help_text": """Management console url as specified by eze management console /profile page
it can also be specified as the environment variable EZE_CONSOLE_ENDPOINT
get EZE_CONSOLE_ENDPOINT from eze management console profile page""",
        },
        "CODEBASE_ID": {
            "type": str,
            "default": "",
            "help_text": """Optional Management console codebase ID as specified by eze management console codebase page,
if not set, git repo url will be automatically determined via local git info and sent""",
        },
        "CODEBRANCH_NAME": {
            "type": str,
            "default": "",
            "help_text": """Optional code branch name,
if not set, will be automatically determined via local git info""",
        },
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return __version__

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output"""
        log("Sending Eze scans to management console:\n")
        self.send_results(scan_results)

    def send_results(self, scan_results: list) -> None:
        """
        Sending results to management console

        :raises EzeError: on send report error
        """
        endpoint = self.config["CONSOLE_ENDPOINT"]
        codebase_id = self.config["CODEBASE_ID"]
        encoded_codebase_id = urllib.parse.quote_plus(codebase_id)
        codebase_name = self.config["CODEBRANCH_NAME"]
        encoded_codebase_name = urllib.parse.quote_plus(codebase_name)
        apikey = self.config["APIKEY"]
        if not apikey:
            log_error("Unable to send report to eze servers, as no APIKEY has been set")
            return
        scan_api_url = f"{endpoint}/v1/api/scan/{encoded_codebase_id}/{encoded_codebase_name}"

        try:
            log(f"scan results to short term storage: {scan_api_url} ({apikey})")
            short_storage_results = self._get_http_json(scan_api_url, scan_results, apikey)
            log(pretty_print_json(short_storage_results))
        except EzeNetworkingError as error:
            raise EzeError(
                f"""Eze Reporter failure to send report to management console
Details:
eze endpoint: {scan_api_url}
codebase id: {codebase_id}
codebase name: {codebase_name}
error: {error}
"""
            )

    def _parse_config(self, config: dict) -> dict:
        """take raw config dict and normalise values"""
        parsed_config = super()._parse_config(config)

        # ADDITION PARSING: CODEBRANCH_ID
        # CODEBRANCH_ID can determined via local git info
        if not parsed_config["CODEBASE_ID"]:
            git_dir = os.getcwd()
            codebase_id = get_active_branch_uri(git_dir)
            if not codebase_id:
                raise EzeConfigError(
                    "requires codebase id or url supplied via 'CODEBASE_ID' config field or a checked out git repo in current dir"
                )
            parsed_config["CODEBASE_ID"] = codebase_id

        # ADDITION PARSING: CODEBRANCH_NAME
        # CODEBRANCH_NAME can determined via local git info
        if not parsed_config["CODEBRANCH_NAME"]:
            git_dir = os.getcwd()
            branch = get_active_branch_name(git_dir)
            if not branch:
                raise EzeConfigError(
                    "requires branch supplied via 'CODEBRANCH_NAME' config field or a checked out git repo in current dir"
                )
            parsed_config["CODEBRANCH_NAME"] = branch

        return parsed_config

    @staticmethod
    def _get_http_json(api_url, body, apikey) -> dict:
        """
        make api call to post endpoint

        :raises EzeNetworkingError: on networking error
        """
        return request_json(
            api_url,
            data=pretty_print_json(body).encode("utf-8"),
            method="POST",
            headers={
                "content-type": "application/json; charset=UTF-8",
                "accept": "application/json, text/plain, */*",
                "x-api-key": apikey,
            },
        )
