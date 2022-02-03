"""CLI test commands"""

import urllib.request
from urllib.error import HTTPError
import urllib.parse
import os
import asyncio
import git
import click

from eze.utils.io import pretty_print_json
from eze.cli.utils.command_helpers import base_options, pass_state
from eze.core.engine import EzeCore
from eze.core.config import EzeConfig
from eze.utils.log import log, log_debug, log_error


@click.command("test")
@base_options
@pass_state
@click.option(
    "--scan-type",
    "-s",
    help="named custom scan type to run aka production can include run type aka 'safety:test-only'",
    required=False,
)
@click.option(
    "--force-autoscan/--dont-force-autoscan",
    help="Forces language autoscan and creation of new .ezerc.toml",
    default=False,
)
@click.option("--autoconfig", type=click.Path(exists=True), help="File with custom autoconfig json", required=False)
def test_command(state, config_file: str, scan_type: str, force_autoscan: bool, autoconfig: click.Path = None) -> None:
    """Eze run scan"""

    EzeCore.auto_build_ezerc(force_autoscan, autoconfig)
    eze_core = EzeCore.get_instance()
    asyncio.run(eze_core.run_scan(scan_type))


@click.command("test-online")
@base_options
@pass_state
@click.option(
    "--url",
    "-u",
    help="Specify the url of the remote repository to run scan. ex https://user:pass@github.com/repo-url",  # nosecret
    required=True,
)
def test_online_command(state, config_file: str, url: str) -> None:
    """Eze run scan remotely on a server"""
    api_key = os.environ.get("EZE_APIKEY", "")
    api_url = os.environ.get("EZE_REMOTE_SCAN_ENDPOINT", "")
    data = {"remote-url": url}
    try:
        req = urllib.request.Request(
            api_url,
            data=pretty_print_json(data).encode("utf-8"),
            headers={"Authorization": api_key},
        )
        with urllib.request.urlopen(req) as response:  # nosec # nosemgrep # using urllib.request.Request
            url_response = response.read()
            log(url_response)
    except HTTPError as err:
        error_text = err.read().decode()
        raise click.ClickException(f"""Error in request: {error_text}""")


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
    help="Specify the url of the remote repository to run scan. ex https://user:pass@github.com/repo-url",  # nosecret
    required=True,
)
@click.option(
    "--branch",
    "-b",
    help="Specify the branch name to run scan against, aka 'main'",
    required=True,
)
def test_remote_command(state, config_file: str, scan_type, url: str, branch: str) -> None:
    """Eze run scan against git repo, and report back to management console"""
    temp_dir = os.path.join(os.getcwd(), "test-remote")

    try:
        os.chdir(temp_dir)
        # TODO: migrate all git helper functions into eze.utils.git
        repo = git.Repo.clone_from(url, temp_dir, branch=branch)
    except git.exc.GitCommandError as error:
        raise click.ClickException("""on cloning process, remote branch not found""")
    os.chdir(temp_dir)

    # rescan for new .ezerc.toml inside downloaded repo
    state.config = EzeConfig.refresh_ezerc_config()
    EzeCore.auto_build_ezerc()

    eze_core = EzeCore.get_instance()
    asyncio.run(eze_core.run_scan(scan_type, ["console", "eze"]))
