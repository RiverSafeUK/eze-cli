"""Helper functions for node based tools"""

import os
import shlex
from pathlib import Path

from eze.utils.cli import run_cmd


class Cache:
    """Cache class container"""


__c = Cache()
__c.installed_dependency = False


def install_node_dependencies():
    """Install node dependencies"""
    if not __c.installed_dependency:
        has_package_json = os.path.isfile(Path.cwd() / "package.json")
        if has_package_json:
            run_cmd(shlex.split("npm install"))
    __c.installed_dependency = True
