"""project tools command"""

import click

from eze.cli.utils.command_helpers import debug_option
from eze.utils.log import log
from eze.utils.language.utils import get_projects


@click.command("projects", short_help="List code projects found in the directory")
@debug_option
def projects_command() -> None:
    """
    List code projects found in the directory
    """
    projects = get_projects()
    for project_name in projects:
        project_list = projects[project_name]
        if len(project_list) > 0:
            log(project_name)
            log("*" * (4 + len(project_name)))
            for project in project_list:
                log("- " + project)
            log("")
