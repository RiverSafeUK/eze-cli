"""CLI tools command"""

import asyncio
import sys

import click

from eze.cli.utils.command_helpers import base_options, pass_state, debug_option
from eze.core.config import EzeConfig
from eze.core.engine import EzeCore
from eze.core.enums import SourceType
from eze.core.tool import ToolManager, ToolType
from eze.utils.config import extract_embedded_run_type
from eze.utils.log import log, log_debug, log_error


@click.group("tools")
@debug_option
def tools_group():
    """container for tool commands"""


@click.command("list", short_help="List the available tools")
@click.option("--tool-type", "-t", help=f"filter by tool type ({','.join(ToolType.__members__)})")
@click.option("--source-type", "-s", help=f"filter by source type ({','.join(SourceType.__members__)})")
@click.option("--include-source-type/--exclude-source-type", default=False, help="adds source type column")
@click.option(
    "--include-version/--exclude-version",
    default=True,
    help="""adds version column
(slow as needs to collect all software versions of tools)""",
)
@click.option("--include-help/--exclude-help", default=False, help="adds all tools documentation")
@debug_option
def list_command(
    tool_type: str, source_type: str, include_source_type: bool, include_version: bool, include_help: bool
) -> None:
    """
    list available tools
    """
    if tool_type and tool_type not in ToolType.__members__:
        log(f"Could not find tool type '{tool_type}'")
        log(f"Available tool types are ({','.join(ToolType.__members__)})")
        sys.exit(1)

    if source_type and source_type not in SourceType.__members__:
        log(f"Could not find source type '{source_type}'")
        log(f"Available source types are ({','.join(SourceType.__members__)})")
        sys.exit(1)

    tool_manager: ToolManager = ToolManager.get_instance()
    tool_manager.print_tools_list(tool_type, source_type, include_source_type, include_version)
    if include_help:
        tool_manager.print_tools_help(tool_type, source_type, include_source_type, include_version)


@click.command("help", short_help="List the help for a given tool")
@click.argument("tool", required=True)
@debug_option
def help_command(tool: str) -> None:
    """
    display help for selected tool
    """
    tool_manager = ToolManager.get_instance()
    if tool not in tool_manager.tools:
        log(f"Could not find tool '{tool}', use 'eze tools list' to get available tools")
        sys.exit(1)

    tool_manager.print_tool_help(tool)


@click.command("run", short_help="Manually run a given tool")
@base_options
@pass_state
@click.argument("tool")  # , help="tool to run aka 'safety' can include run type aka 'safety:test-only'"
@click.option("--report", "-r", help="named report type to run aka console", default="console")
@click.option(
    "--scan-type",
    "-s",
    help="named custom scan type to run aka production can include run type aka 'safety:test-only'",
    required=False,
)
def run_command(state, config_file: str, tool: str, report: str = "console", scan_type: str = None) -> None:
    """
    manually run a scan using given tool

    aka

    eze tools run safety --debug
    """
    if EzeConfig.debug_mode:
        print(
            f"""Running scan:
=========================
    tool: {tool}
    report: {report}
    scan_type: {scan_type if scan_type else 'default'}
"""
        )

    [tool_name, run_type] = extract_embedded_run_type(tool)

    tool_manager = ToolManager.get_instance()
    if tool_name not in tool_manager.tools:
        log(f"Could not find tool '{tool_name}', use 'eze tools list' to get available tools")
        sys.exit(1)
    tool_class = tool_manager.tools[tool_name]
    tool_version = tool_class.check_installed()
    if not tool_version:
        log(
            f"'{tool_name}' Tool not installed, use 'eze tools help --tool {tool_name}' to get help installing {tool_name}"
        )
        sys.exit(1)

    eze_core = EzeCore.get_instance()

    asyncio.run(eze_core.run([tool], [], [report], scan_type))


tools_group.add_command(list_command)
tools_group.add_command(help_command)
tools_group.add_command(run_command)
