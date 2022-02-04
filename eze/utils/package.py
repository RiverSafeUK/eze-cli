"""Basic plugin engine

Follows standard python conventions set out in
https://packaging.python.org/guides/creating-and-discovering-plugins/
https://setuptools.readthedocs.io/en/latest/setuptools.html#dynamic-discovery-of-services-and-plugins

In order to create a plugin

1) Register your app as one to be included via entry_points

in your setup.py include
entry_points={'eze.plugins': 'xxx = eze_plugin_xxx'},

2) Register the new notification output or scan engine

def get_reporters() -> dict[str,ReporterMeta]:
    ... this is called on plugin initialisation

def get_tools() -> dict[str,ToolMeta]:
    ... this is called on plugin initialisation

3) Enable new notification engines and scan engines
"""

import pkg_resources

from eze.plugins import base_plugins
from eze.utils.log import log

EZE_ENTRY_POINT_PREFIX = "eze.plugins"


def get_plugins() -> dict:
    """Get all plugins prefixed eze_"""
    discovered_plugins = {"inbuilt": base_plugins}
    for entry_point in pkg_resources.iter_entry_points(EZE_ENTRY_POINT_PREFIX):
        if entry_point.name in discovered_plugins:
            log(f"-- skipping plugin {entry_point.name} as already loaded")
            continue
        discovered_plugins[entry_point.name] = entry_point.load()

    return discovered_plugins
