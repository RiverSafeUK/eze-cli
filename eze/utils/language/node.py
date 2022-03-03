"""Helper functions for node based tools"""

import os
import shlex
from pathlib import Path

from pydash import py_

from eze.utils.io.file import parse_json

from eze.utils.cli.run import run_async_cmd


class Cache:
    """Cache class container"""


__c = Cache()
__c.installed_in_folder = {}


def delete_npm_cache() -> None:
    """delete npm caching"""
    __c.installed_in_folder = {}


async def install_npm_in_path(raw_path):
    """Install node dependencies"""
    lookup_key: str = str(raw_path)
    path = Path.joinpath(Path.cwd(), raw_path)
    if not lookup_key in __c.installed_in_folder:
        has_package_json = os.path.isfile(path / "package.json")
        if has_package_json:
            await run_async_cmd(shlex.split("npm install"), cwd=path)
    __c.installed_in_folder[lookup_key] = True


async def annotate_transitive_licenses(sbom: dict, project_folder: str, include_dev: True) -> dict:
    """adding annotations to licenses which are not top-level"""
    cmd = "npm list --json" if include_dev else "npm list --json --only=prod"
    completed_process = await run_async_cmd(shlex.split(cmd), cwd=project_folder)
    report_text = completed_process.stdout
    parsed_json = parse_json(report_text)
    top_level_packages = py_.get(parsed_json, "dependencies", {})
    for component in py_.get(sbom, "components", []):
        component_name = component["name"]
        is_not_transitive = component_name in top_level_packages
        py_.set(component, "properties.transitive", not is_not_transitive)
    return top_level_packages
