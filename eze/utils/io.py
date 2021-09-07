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

import click
import toml


class ClickManagedFileAccessError(click.ClickException):
    pass


def normalise_file_paths(file_paths: list) -> Path:
    """Clean up user inputted filename path makes all"""
    new_file_paths = list(map(normalise_linux_file_path, file_paths))
    return new_file_paths


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


def pretty_print_json(obj) -> str:
    """Helper, takes generic python class/object and convert into pretty json str"""
    return json.dumps(obj, default=vars, indent=2, sort_keys=True)


def load_text(file_path: str) -> str:
    """Load text file"""
    try:
        with open(file_path, "r", encoding="utf-8") as text_file:
            text_str = text_file.read()
        text_file.close()
        return text_str

    except PermissionError as not_permitted_err:
        raise ClickManagedFileAccessError(f"Eze cannot access '{not_permitted_err.filename}', Permission was denied")
    except FileNotFoundError as not_found_err:
        raise ClickManagedFileAccessError(f"Eze cannot access '{not_found_err.filename}', File could not be found")


def load_toml(file_path: str) -> str:
    """Load toml file"""
    toml_str = load_text(file_path)
    parsed_toml = toml.loads(toml_str)
    return parsed_toml


def load_json(file_path: str):
    """Load json file and convert to dict"""
    json_str = load_text(file_path)
    if not json_str:
        return []
    python_obj = json.loads(json_str)
    return python_obj


def create_folder(file_path: str):
    """Create folder to location file"""
    location = get_absolute_filename(file_path)
    path = os.path.dirname(location)
    try:
        os.makedirs(path, exist_ok=True)

    except PermissionError as not_permitted_err:
        raise ClickManagedFileAccessError(
            f"Eze cannot create folder '{not_permitted_err.filename}', Permission was denied"
        )


def write_text(file_path: str, text: str) -> str:
    """Save text file"""
    create_folder(file_path)
    location = get_absolute_filename(file_path)
    try:
        with open(location, mode="w") as text_file:
            text_file.write(text)
        text_file.close()
        return location
    except PermissionError as not_permitted_err:
        raise ClickManagedFileAccessError(f"Eze cannot write '{not_permitted_err.filename}', Permission was denied")


def write_json(file_path: str, json_vo) -> str:
    """Save json file"""
    json_str = pretty_print_json(json_vo)
    json_location = write_text(file_path, json_str)
    return json_location


def xescape(fragment: str) -> str:
    """Helper, escapes xml attribute strings prevents xml expansion attacks"""
    if not fragment:
        if fragment == 0:
            return "0"
        return ""
    return escape(str(fragment), {'"': "&quot;", "'": "&apos;", "<": "&lt;", ">": "&gt;", "\\": "&#92;"})


def exit_app(error_message: str) -> str:
    """Helper, will exit application with code and message"""
    raise click.ClickException(error_message)


def create_tempfile_path(filename: str) -> str:
    """create a tempfile path, ensure folder exists"""
    eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
    tmp_report_file = Path(tempfile.gettempdir()) / ".eze-temp" / filename
    os.makedirs(eze_temp_folder, exist_ok=True)
    return tmp_report_file


def delete_file(filename: str):
    """Delete path with no errors"""
    try:
        os.remove(filename)
    except FileNotFoundError:
        pass
