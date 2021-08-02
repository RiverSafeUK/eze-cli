"""CLI remote test command"""

import asyncio
from eze.cli.utils.config import set_eze_config

from git import Repo
import git
import os
import click

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
def test_remote_commands(state, config_file: str, scan_type, url: str) -> None:
    """Eze run scan in a remote repository"""
    temp_dir = os.path.join(os.getcwd(), "test-remote")
    repo = git.Repo.clone_from(
        url,
        temp_dir,
    )
    os.chdir(temp_dir)
    state.config = set_eze_config(None)
    eze_core = EzeCore.get_instance()
    asyncio.run(eze_core.run_scan(scan_type))
