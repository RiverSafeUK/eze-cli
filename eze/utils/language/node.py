"""Helper functions for node based tools"""

import os
import shlex
from pathlib import Path

from eze.utils.cli import run_async_cmd


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
