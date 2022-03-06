"""Eze's Auto configuration module"""
from __future__ import annotations

import json
import os
from pathlib import Path
from pydash import py_

from eze.core.config import EzeConfig
from eze.core.enums import (
    LICENSE_DENYLIST_CONFIG,
    LICENSE_ALLOWLIST_CONFIG,
)
from eze.utils.io.file import write_text, load_json
from eze.utils.log import log, log_debug
from eze.utils.io.file_scanner import find_files_by_name, has_filetype


class AutoConfigRunner:
    """Base class AutoConfig"""

    @staticmethod
    def _is_tool_enabled(tool_config: dict, tool_id: str) -> bool:
        """is tool enabled"""
        if py_.get(tool_config, "enabled_always", False):
            log_debug(f"enabling {tool_id}, always enabled")
            return True
        enable_files = py_.get(tool_config, "enable_on_file", False)
        if enable_files:
            for enable_file in enable_files:
                if len(find_files_by_name(enable_file)) > 0:
                    log_debug(f"enabling {tool_id}, found {enable_file}")
                    return True
        enable_file_exts = py_.get(tool_config, "enable_on_file_ext", False)
        if enable_file_exts:
            for enable_file_ext in enable_file_exts:
                if has_filetype(enable_file_ext) > 0:
                    log_debug(f"enabling {tool_id}, found {enable_file_ext}")
                    return True
        return False

    @staticmethod
    def _create_tool_config_fragment(tool_config: dict, tool_id: str) -> str:
        """create ezerc.toml tool fragment"""
        newline_char = "\n"
        fields_txt = []
        fields = py_.get(tool_config, "config", {})
        for field_id in fields:
            fields_txt.append(f"{field_id} = {json.dumps(fields[field_id], default=vars)}")
        return f"""[{tool_id}]
# Full List of Fields and Tool Help available "docker run riversafe/eze-cli tools help {tool_id}"
{newline_char.join(fields_txt)}
"""

    @staticmethod
    def _create_reporter_config_fragment(reporter_config: dict, reporter_id: str) -> str:
        """create ezerc.toml reporter fragment"""
        newline_char = "\n"
        fields_txt = []
        fields = py_.get(reporter_config, "config", {})
        for field_id in fields:
            fields_txt.append(f"{field_id} = {json.dumps(fields[field_id], default=vars)}")
        return f"""[{reporter_id}]
# Full List of Fields and Reporter Help available "docker run riversafe/eze-cli reporters help {reporter_id}"
{newline_char.join(fields_txt)}
"""

    @staticmethod
    def _create_tools_config(autoconfig_json: dict = None) -> list:
        tool_configs = py_.get(autoconfig_json, "tools", {})
        tool_config_fragments = []
        tool_list = []
        for tool_id in tool_configs:
            tool_config = tool_configs[tool_id]
            is_enabled = AutoConfigRunner._is_tool_enabled(tool_config, tool_id)
            if not is_enabled:
                continue
            tool_list.append(json.dumps(tool_id, default=vars))
            tool_config_fragments.append(AutoConfigRunner._create_tool_config_fragment(tool_config, tool_id))

        return [tool_config_fragments, tool_list]

    @staticmethod
    def _create_reporters_config(autoconfig_json: dict = None) -> list:
        reporter_configs = py_.get(autoconfig_json, "reporters", {})
        reporter_config_fragments = []
        reporter_list = []
        for reporter_id in reporter_configs:
            reporter_config = reporter_configs[reporter_id]
            reporter_list.append(json.dumps(reporter_id, default=vars))
            reporter_config_fragments.append(
                AutoConfigRunner._create_reporter_config_fragment(reporter_config, reporter_id)
            )
        return [reporter_config_fragments, reporter_list]

    @staticmethod
    def create_ezerc_text(autoconfig_json: dict = None) -> str:
        """Method for building a dynamic ezerc.toml fragment"""
        license_mode = py_.get(autoconfig_json, "license.license_mode", "PROPRIETARY")
        [tool_config_fragments, tool_list] = AutoConfigRunner._create_tools_config(autoconfig_json)
        [reporter_config_fragments, reporter_list] = AutoConfigRunner._create_reporters_config(autoconfig_json)

        newline_char = "\n"
        fragment = f"""
# auto generated .ezerc.toml
# recreate with "docker run -t --rm -v DIRECTORY:/data riversafe/eze-cli housekeeping create-local-config"

# ===================================
# GLOBAL CONFIG
# ===================================
[global]
# LICENSE_CHECK, available modes:
# - PROPRIETARY (default) : for commercial projects, check for non-commercial, strong-copyleft, and source-available licenses
# - PERMISSIVE : for permissive open source projects (aka MIT, LGPL), check for strong-copyleft licenses
# - OPENSOURCE : for copyleft open source projects (aka GPL), check for non-OSI or FsfLibre certified licenses
# - OFF : no license checks
# All modes will also warn on "unprofessional", "deprecated", and "permissive with conditions" licenses
LICENSE_CHECK = "{license_mode}"
# LICENSE_ALLOWLIST, {LICENSE_ALLOWLIST_CONFIG["help_text"]}
LICENSE_ALLOWLIST = []
# LICENSE_DENYLIST, {LICENSE_DENYLIST_CONFIG["help_text"]}
LICENSE_DENYLIST = []

# speeds up SAST tools by using copied folder with no binary/dependencies assets
# for mono-repos can speed up scans from 800s to 30s, by avoiding common dependencies such as node_modules
# stored: TMP/.eze/cached-workspace
USE_SOURCE_COPY = true

# Should SCA scan test or development dependencies
INCLUDE_DEV = false

# ========================================
# TOOL CONFIG
# ========================================
# run for available tools "docker run -t --rm riversafe/eze-cli tools list"
{newline_char.join(tool_config_fragments)}

# ========================================
# REPORT CONFIG
# ========================================
# run for available reporters "docker run -t --rm riversafe/eze-cli reporters list"
{newline_char.join(reporter_config_fragments)}

# ========================================
# SCAN CONFIG
# ========================================
[scan]
tools = [{','.join(tool_list)}]
reporters = [{','.join(reporter_list)}]
"""
        return fragment

    @staticmethod
    def get_autoconfig(autoconfig_file: str = None) -> dict:
        """get autoconfig data, defaults to from eze/data/default_autoconfig.json"""
        if not autoconfig_file:
            file_dir = os.path.dirname(__file__)
            autoconfig_file = Path(file_dir) / ".." / "data" / "default_autoconfig.json"
        return load_json(autoconfig_file)

    @classmethod
    def create_local_ezerc_config(cls, autoconfig_file: str = None) -> bool:
        """Create new local ezerc file"""
        autoconfig_data = cls.get_autoconfig(autoconfig_file)
        eze_rc = cls.create_ezerc_text(autoconfig_data)
        local_config_location = EzeConfig.get_local_config_filename()
        write_text(str(local_config_location), eze_rc)
        log(f"Successfully written configuration file to '{local_config_location}'")

        return True
