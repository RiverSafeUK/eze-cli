"""CLI test commands"""
import textwrap
import urllib.request
from urllib.error import HTTPError
import urllib.parse
import os
import asyncio
import git
import click
from eze.utils.io.print import pretty_print_json
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
def call_remote_scan_endpoint(state, config_file: str, url: str) -> None:
    """Makes a call to the api to run eze scan remotely on a server"""
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
@click.option("--branch", "-b", help="Specify the branch name to run scan against, aka 'main'", default="main")
@click.option("--s3-bucket", "-s", help="Specify the s3 bucket where to upload the file")
@click.option("--s3-file", "-f", help="Specify the filename")
def run_eze_scan_on_git_remote_repo(
    state, config_file: str, scan_type, url: str, branch: str, s3_bucket: str, s3_file: str
) -> None:
    """Pull a remote repository from git and run eze scan, report back (via s3 bucket 's3' or management console 'eze')"""
    temp_dir = os.path.join(os.getcwd(), "test-remote")

    try:
        os.chdir(temp_dir)
        # TODO: migrate all git helper functions into eze.utils.git
        repo = git.Repo.clone_from(url, temp_dir, branch=branch)
    except git.exc.GitCommandError as error:
        raise click.ClickException(f"""on cloning remote branch '{branch}' process, {error.stderr}""")
    os.chdir(temp_dir)
    # rescan for new .ezerc.toml inside downloaded repo
    state.config = EzeConfig.refresh_ezerc_config()
    EzeCore.auto_build_ezerc()

    if s3_bucket is None:
        eze_core = EzeCore.get_instance()
        asyncio.run(eze_core.run_scan(scan_type, ["console", "eze"]))

    else:
        config_file = EzeConfig.get_local_config_filename()
        with open(config_file, "a", encoding="utf-8") as toml:
            toml.write(
                textwrap.dedent(
                    f"""
    [s3.test]
    BUCKET_NAME = "{s3_bucket}"
    OBJECT_KEY = "{s3_file}.json"
             """
                )
            )

        state.config = EzeConfig.refresh_ezerc_config()

        eze_core = EzeCore.get_instance()
        asyncio.run(eze_core.run_scan("test", ["s3:test"]))
