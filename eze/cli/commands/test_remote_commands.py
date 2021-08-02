"""CLI remote test command"""

import asyncio
from eze.utils.io import pretty_print_json
from eze.cli.utils.config import set_eze_config

from git import Repo
import git
import os
import click
import urllib.request
from urllib.error import HTTPError
import urllib.parse

from eze.cli.utils.command_helpers import base_options, pass_state, debug_option
from eze.core.engine import EzeCore


@click.command("test-remote")
@base_options
@pass_state
@click.option(
    "--scan-type",
    "-s",
    help="named custom scan type to run aka production can include run type aka 'safety:test-only'",
    required=False,
)
@click.option(
    "--url",
    "-u",
    help="Especify the url of the remote repository to run scan. ex https://user:pass@github.com/repo-url",
    required=True,
)
@click.option(
    "--online",
    is_flag=True,
    help="Especify if you want to run the test online instead of locally",
)
def test_remote_commands(state, config_file: str, scan_type, url: str, online: bool) -> None:
    """Eze run scan in a remote repository"""
    if online:
        api_url = "https://lff3adj48f.execute-api.eu-west-2.amazonaws.com/staging/v1/api/remote-scan"
        data = {"remote-url": url}
        try:
            req = urllib.request.Request(
                api_url, data=pretty_print_json(data).encode("utf-8"), headers={"Authorization": "---"}
            )
            with urllib.request.urlopen(req) as response:
                url_response = response.read()
                print(url_response)
        except HTTPError as err:
            error_text = err.read().decode()
            raise click.ClickException(f"""Error in request: {error_text}""")
    else:
        temp_dir = os.path.join(os.getcwd(), "test-remote")
        repo = git.Repo.clone_from(
            url,
            temp_dir,
        )
        os.chdir(temp_dir)
        state.config = set_eze_config(None)
        eze_core = EzeCore.get_instance()
        asyncio.run(eze_core.run_scan(scan_type))
