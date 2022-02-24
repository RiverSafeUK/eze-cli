"""IO helpers
"""
import json
import os
import re
import tempfile
from pathlib import Path

# INFO: saxutils.escape not insecure, it's xml.sax, no xml attribute escape equivilent in defused
# https://github.com/PyCQA/bandit/issues/452
from xml.sax.saxutils import escape  # nosec # nosemgrep

import xmltodict
import click
import toml
from eze.utils.io.print import pretty_print_json

from eze.utils.error import EzeFileAccessError, EzeFileParsingError
from eze.utils.log import log, log_debug, log_error


def sane(key):
    """sanitise keys to be Alpha-numerical"""
    if not key:
        return ""
    return re.sub("[^a-zA-Z0-9_-]", "_", key)


def normalise_file_paths(file_paths: list) -> Path:
    """Clean up user inputted filename path makes all"""
    new_file_paths = list(map(normalise_linux_file_path, file_paths))
    return new_file_paths


def remove_non_folders(file_paths: list, default: list, subject: str) -> list:
    """Removes non folders and non existent entries"""
    cleaned = []
    for file_path in file_paths:
        local_folder = Path.cwd() / file_path
        if not os.path.exists(local_folder):
            continue
        if not os.path.isdir(local_folder):
            log(f"{subject}: Removing non folder '{local_folder}' from list '{file_paths}'")
            continue
        cleaned.append(file_path)
    if len(cleaned) == 0:
        log(f"{subject}: No valid paths left, defaulting to '{default}'")
        return default
    return cleaned


def is_windows_os() -> bool:
    """Is running on a windows machine
    see https://docs.python.org/3/library/os.html
    """
    os_name = os.name
    return os_name == "nt"


def normalise_linux_file_path(file_path: str) -> Path:
    """Clean up user inputted filename path makes all back slashes forward slashes"""
    file_path = re.sub("\\\\", "/", file_path)
    return file_path


def normalise_windows_regex_file_path(file_path: str) -> Path:
    """Clean up user inputted filename path makes all forward 4 escaped back slashes slashes"""
    file_path = re.sub("/", "\\\\\\\\", file_path)
    return file_path


def get_absolute_filename(user_inputted_filename: str) -> Path:
    """Clean up user inputted filename path, wraps os.path.abspath, returns Path object"""
    filename_location = Path(os.path.abspath(user_inputted_filename))
    return filename_location


def load_text(file_path: str) -> str:
    """
    Load text file

    :raises EzeFileAccessError
    """
    try:
        with open(file_path, "r", encoding="utf-8") as text_file:
            text_str = text_file.read()
        text_file.close()
        return text_str

    except PermissionError as not_permitted_err:
        raise EzeFileAccessError(f"Eze cannot access '{not_permitted_err.filename}', Permission was denied")
    except FileNotFoundError as not_found_err:
        raise EzeFileAccessError(f"Eze cannot access '{not_found_err.filename}', File could not be found")


def load_toml(file_path: str) -> str:
    """
    Load toml file

    :raises EzeFileAccessError
    :raises EzeFileParsingError
    """
    toml_str = load_text(file_path)

    try:
        return toml.loads(toml_str)
    except toml.TomlDecodeError as error:
        raise EzeFileParsingError(
            f"Unable to parse TOML file '{file_path}', message: '{error.msg}' (line {error.lineno})"
        )


def parse_json(json_str: str):
    """
    Load json string and convert to dict

    :raises EzeFileAccessError
    :raises EzeFileParsingError
    """
    try:
        return json.loads(json_str)
    except json.decoder.JSONDecodeError as error:
        raise EzeFileParsingError(f"Unable to parse JSON fragment, message: '{error.msg}' (line {error.lineno})")


def load_json(file_path: str):
    """
    Load json file and convert to dict

    :raises EzeFileAccessError
    :raises EzeFileParsingError
    """
    json_str = load_text(file_path)
    if not json_str:
        return []
    try:
        return json.loads(json_str)
    except json.decoder.JSONDecodeError as error:
        raise EzeFileParsingError(
            f"Unable to parse JSON file '{file_path}', message: '{error.msg}' (line {error.lineno})"
        )


def load_xml(file_path: str, force_list: dict = None):
    """
    Load xml file and convert to dict

    :raises EzeFileAccessError
    :raises EzeFileParsingError
    """
    xml_str = load_text(file_path)
    try:
        return xmltodict.parse(xml_str, force_list=force_list or {})
    except xmltodict.ParsingInterrupted as error:
        raise EzeFileParsingError(f"Unable to parse XML file '{file_path}', Error: {error}")
    except ValueError as error:
        raise EzeFileParsingError(f"Unable to parse XML file '{file_path}', Error: {error}")


def create_folder(file_path: str, raise_error_on_fail: bool = True):
    """
    Create folder to location file

    :raises EzeFileAccessError
    """
    location = get_absolute_filename(file_path)
    path = os.path.dirname(location)
    try:
        os.makedirs(path, exist_ok=True)
    except PermissionError as not_permitted_err:
        if raise_error_on_fail:
            raise EzeFileAccessError(f"Eze cannot create folder '{not_permitted_err.filename}', Permission was denied")
        log_error(f"Eze cannot create folder '{not_permitted_err.filename}', Permission was denied")


def write_text(file_path: str, text: str) -> str:
    """
    Save text file

    :raises EzeFileAccessError
    """
    create_folder(file_path)
    location = get_absolute_filename(file_path)
    try:
        with open(location, mode="w") as text_file:
            text_file.write(text)
        text_file.close()
        return location
    except PermissionError as not_permitted_err:
        raise EzeFileAccessError(f"Eze cannot write '{not_permitted_err.filename}', Permission was denied")


def write_json(file_path: str, json_vo) -> str:
    """
    Save json file

    :raises EzeFileAccessError
    """
    json_str = pretty_print_json(json_vo)
    json_location = write_text(file_path, json_str)
    return json_location


def write_sarif(file_path: str, json_vo) -> str:
    """
    Save sarif file

    :raises EzeFileAccessError
    """
    sarif_str = json.dumps(json_vo, default=vars, indent=2, sort_keys=False)
    sarif_location = write_text(file_path, sarif_str)
    return sarif_location


def xescape(fragment: str) -> str:
    """Helper, escapes xml attribute strings prevents xml expansion attacks"""
    if not fragment:
        if fragment == 0:
            return "0"
        return ""
    return escape(str(fragment), {'"': "&quot;", "'": "&apos;", "<": "&lt;", ">": "&gt;", "\\": "&#92;"})


def exit_app(error_message: str) -> str:
    """
    Helper, will exit application with code and message

    :raises click.ClickException
    """
    raise click.ClickException(error_message)


def create_absolute_path(file_path: str, cwd: str = None) -> str:
    """create absolute path from a absolute or relative path"""
    if Path(file_path).is_absolute():
        return file_path
    if not cwd:
        cwd = Path.cwd()
    return Path(cwd) / file_path


def create_tempfile_path(filename: str) -> str:
    """create a tempfile path, ensure folder exists"""
    eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
    tmp_report_file = Path(tempfile.gettempdir()) / ".eze-temp" / filename
    os.makedirs(eze_temp_folder, exist_ok=True)
    return tmp_report_file


def create_tempfile_folder(folder: str) -> str:
    """create a tempfile path, ensure folder exists"""
    working_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp", folder)
    os.makedirs(working_temp_folder, exist_ok=True)
    return working_temp_folder


def delete_file(filename: str):
    """Delete path with no errors"""
    try:
        os.remove(filename)
    except FileNotFoundError:
        pass
