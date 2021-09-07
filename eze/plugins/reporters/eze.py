"""Eze reporter class implementation"""
import os
import urllib.request
from urllib import request
from urllib.error import HTTPError

import click

from eze import __version__
from eze.core.config import ConfigException
from eze.core.reporter import ReporterMeta
from eze.core.tool import ScanResult
from eze.utils.git import get_active_branch_name
from eze.utils.io import pretty_print_json


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
            "required": True,
            "default": os.environ.get("EZE_APIKEY", ""),
            "default_help_value": "ENVIRONMENT VARIABLE <EZE_APIKEY>",
            "help_text": """WARNING: APIKEY should be kept in your global system config and not stored in version control .ezerc.toml
it can also be specified as the environment variable EZE_APIKEY
get EZE_APIKEY from eze console profile page""",
        },
        "CONSOLE_ENDPOINT": {
            "type": str,
            "required": True,
            "help_text": "Management console url as specified by eze management console /profile page",
        },
        "CODEBASE_ID": {
            "type": str,
            "required": True,
            "help_text": "Management console codebase ID as specified by eze management console codebase page",
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
        click.echo("Sending Eze scans to management console:\n")
        self.send_results(scan_results)

    def send_results(self, scan_results: ScanResult) -> str:
        """Sending results to management console"""
        endpoint = self.config["CONSOLE_ENDPOINT"]
        codebase_id = self.config["CODEBASE_ID"]
        encoded_codebase_id = urllib.parse.quote_plus(codebase_id)
        codebase_name = self.config["CODEBRANCH_NAME"]
        encoded_codebase_name = urllib.parse.quote_plus(codebase_name)
        apikey = self.config["APIKEY"]
        api_url = f"{endpoint}/v1/api/scan/{encoded_codebase_id}/{encoded_codebase_name}"

        try:
            req = request.Request(
                api_url,
                data=pretty_print_json(scan_results).encode("utf-8"),
                method="POST",
                headers={
                    "content-type": "application/json; charset=UTF-8",
                    "accept": "application/json, text/plain, */*",
                    "x-api-key": apikey,
                },
            )
            # nosec: Request is being built directly above as a explicit http request
            # hence no risk of unexpected scheme
            with urllib.request.urlopen(req) as stream:  # nosec # nosemgrep
                contents = stream.read()
            click.echo(contents)
        except HTTPError as err:
            error_text = err.read().decode()
            raise click.ClickException(
                f"""Eze Reporter failure to send report to management console
Details:
eze endpoint url: {api_url}
code: {err.status} ({err.reason})
reply: {error_text}
codebase id: {codebase_id}
codebase name: {codebase_name}
"""
            )

    def _parse_config(self, config: dict) -> dict:
        """take raw config dict and normalise values"""
        parsed_config = super()._parse_config(config)

        # ADDITION PARSING: CODEBRANCH_NAME
        # CODEBRANCH_NAME can determined via local git info
        if not parsed_config["CODEBRANCH_NAME"]:
            git_dir = os.getcwd()
            branch = get_active_branch_name(git_dir)
            if not branch:
                raise ConfigException(
                    "requires branch supplied via 'CODEBRANCH_NAME' config field or a checked out git repo in current dir"
                )
            parsed_config["CODEBRANCH_NAME"] = branch

        return parsed_config
