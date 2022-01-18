"""Basic cli helpers utils

by wrapping the cli tools in a framework, safety execution and sanitation of parameters can be achieved
and making sure debugging of command can be achieved without exposing as apikeys/secrets in raw cli command

Handles management of constructing and running a cli securely

Parts of a cli command
- command aka ls
- arguments aka some.json
  (special case: some programs require these to be after flags hence TAIL_ARGUMENTS)
  ARGUMENTS
- short/long flags aka -v / --version
  SHORT_FLAGS
- flag argument aka -s=foo / --source=foo / -s foo / --source foo
  FLAGS
- flag multiple argument aka -s foo1 foo2/ --source foo1 foo2
  FLAGS_WITH_MULTI_FIELDS

<command> <arguments> <short-flags> <flag-arguments> <tail-arguments>

aka
ls . -man
"""
import asyncio
import re
import shlex
import shutil

# nosec: Subprocess is inherently required to run cli tools, hence is a necessary security risk
import subprocess  # nosec

from eze.utils.io import is_windows_os
import eze.utils.windowslex as windowslex
from eze.utils.error import EzeExecutableNotFoundError, EzeExecutableStdErrError
from eze.utils.log import log_debug
from eze.utils.semvar import is_semvar


class CompletedProcess:
    """completed process output container"""

    def __init__(self, stdout: str, stderr: str = ""):
        """constructor"""
        self.stdout = stdout
        self.stderr = stderr


def run_cli_command(
    cli_config: dict, config: dict = None, command_name: str = "", throw_error_on_stderr: bool = False
) -> CompletedProcess:
    """
    Run tool cli command

    cli_config: dict
        BASE_COMMAND command to start with
        ARGUMENTS list of arguments to add (at start)
        TAIL_ARGUMENTS list of arguments to add (at end)
        FLAGS config-key flag-value pairs
        SHORT_FLAGS config-key flag (value if truthy will set flag)

    config: dict
        config-key for FLAGS command
        + inbuilt key ADDITIONAL_ARGUMENTS

    :raises EzeExecutableNotFoundError
    :raises EzeExecutableStdErrError
    """
    if not config:
        config = {}
    command_list = build_cli_command(cli_config, config)
    completed_process = run_cmd(command_list)

    log_debug(f"""ran command '{command_name}'""")

    if completed_process.stderr:
        sanitised_command_str = __sanitise_command(command_list)
        message = f"""{command_name} ran with warnings/errors:
    Ran: '{sanitised_command_str}'
    Output: {completed_process.stdout}
    Error: {completed_process.stderr}"""
        log_debug(message)
        if throw_error_on_stderr:
            raise EzeExecutableStdErrError(message)
    return completed_process


async def run_async_cli_command(
    cli_config: dict, config: dict = None, command_name: str = "", throw_error_on_stderr: bool = False
) -> CompletedProcess:
    """
    Run tool cli command

    cli_config: dict
        BASE_COMMAND command to start with
        ARGUMENTS list of arguments to add (at start)
        TAIL_ARGUMENTS list of arguments to add (at end)
        FLAGS config-key flag-value pairs
        SHORT_FLAGS config-key flag (value if truthy will set flag)

    config: dict
        config-key for FLAGS command
        + inbuilt key ADDITIONAL_ARGUMENTS

    :raises EzeExecutableNotFoundError
    :raises EzeExecutableStdErrError
    """
    if not config:
        config = {}
    command_list = build_cli_command(cli_config, config)
    completed_process = await run_async_cmd(command_list)

    log_debug(
        f"""{command_name} ran with output:
    {completed_process.stdout}"""
    )

    if completed_process.stderr:
        sanitised_command_str = __sanitise_command(command_list)
        message = f"""{command_name} ran with warnings/errors:
    Ran: '{sanitised_command_str}'
    Error: {completed_process.stderr}"""
        log_debug(message)
        if throw_error_on_stderr:
            raise EzeExecutableStdErrError(message)
    return completed_process


def _append_to_list(command_list: list, appendees, config: dict) -> str:
    """annotate command string with appendees which are "dict args=config-key kv" or "list of config-keys" """
    for config_key in appendees:
        flag_arg = ""
        if isinstance(appendees, dict):
            flag_arg = appendees[config_key]
        config_value = config.get(config_key, "")
        if config_value:
            # is multiple values
            if isinstance(config_value, list):
                for multi_config_value in config_value:
                    command_list += _create_parameter_list(flag_arg, multi_config_value)
            else:
                command_list += _create_parameter_list(flag_arg, config_value)
    return command_list


def _append_multi_value_to_list(command_list: list, appendees, config: dict) -> str:
    """annotate command string with appendees which are "dict args=config-key kv" or "list of config-keys" """
    for config_key in appendees:
        flag_arg = ""
        if isinstance(appendees, dict):
            flag_arg = appendees[config_key]
        config_value = config.get(config_key, "")
        if config_value:
            command_list += [flag_arg]
            # is multiple values
            if isinstance(config_value, list):
                command_list += config_value
            else:
                command_list += [config_value]
    return command_list


def _append_short_flags_to_list(command_list: list, appendees, config: dict) -> str:
    """annotate command string with appendees which are "dict args=config-key kv" or "list of config-keys" """
    for config_key in appendees:
        flag_arg = ""
        if isinstance(appendees, dict):
            flag_arg = appendees[config_key]
        config_value = config.get(config_key, "")
        if flag_arg and config_value:
            command_list += [flag_arg]
    return command_list


def _create_parameter_list(flag_key: str, flag_value: str) -> list:
    """ "Create parameter fragment from flag=value"""
    if not flag_key:
        flag_key = ""
    if flag_value:
        flag_value = shlex.quote(str(flag_value))
    return shlex.split(f"{flag_key}{flag_value}")


def build_cli_command(cli_config: dict, config: dict) -> list:
    """Build tool cli command

    cli_config: dict
        BASE_COMMAND:list command to start with
        ARGUMENTS list of arguments to add (at start)
        TAIL_ARGUMENTS list of arguments to add (at end)
        SHORT_FLAGS short/long flags aka -v / --version
        FLAGS config-key flag-value pairs
        FLAGS_WITH_MULTI_FIELDS config-key flag-<value list> pairs

    config: dict
        config-key for FLAGS command
        + inbuilt key ADDITIONAL_ARGUMENTS
    """
    command_list = [] + cli_config["BASE_COMMAND"]

    argument_keys = cli_config.get("ARGUMENTS", [])
    command_list = _append_to_list(command_list, argument_keys, config)

    argument_keys = cli_config.get("SHORT_FLAGS", {})
    command_list = _append_short_flags_to_list(command_list, argument_keys, config)

    argument_keys = cli_config.get("FLAGS", {})
    command_list = _append_to_list(command_list, argument_keys, config)

    argument_keys = cli_config.get("FLAGS_WITH_MULTI_FIELDS", {})
    command_list = _append_multi_value_to_list(command_list, argument_keys, config)

    argument_keys = cli_config.get("TAIL_ARGUMENTS", {})
    command_list = _append_to_list(command_list, argument_keys, config)

    additional_args = config.get("ADDITIONAL_ARGUMENTS", "")
    if additional_args:
        command_list += shlex.split(additional_args)
    return command_list


def crossos_shlex_join(cmd: list) -> list:
    """creates safe cmd string from a list of arguments, due to windows and unix require different shlex.join commands"""
    if is_windows_os():
        final_cmd = windowslex.join(cmd)
    else:
        final_cmd = shlex.join(cmd)
    return final_cmd


async def async_subprocess_run(cmd: list) -> CompletedProcess:
    """runs a subprocess asynchronously via asyncio.create_subprocess_shell"""
    final_cmd = crossos_shlex_join(cmd)
    # nosec: Subprocess with shell=True is inherently required to run the cli tools, hence is a necessary security risk
    # WORKAROUND: many programming tools failing without shell=true
    # aka: unable to access JAVA_HOME without shell unfortunately, hence mvn command fails
    # see https://stackoverflow.com/questions/28420087/how-to-get-maven-to-work-with-python-subprocess
    process = await asyncio.create_subprocess_shell(
        final_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    await process.wait()
    stdout, stderr = await process.communicate()
    process_output = CompletedProcess(stdout.decode(), stderr.decode())
    return process_output


def subprocess_run(cmd: list) -> CompletedProcess:
    """runs a subprocess synchronously via subprocess.run"""
    final_cmd = crossos_shlex_join(cmd)
    # nosec: Subprocess with shell=True is inherently required to run the cli tools, hence is a necessary security risk
    # also map ADDITIONAL_ARGUMENTS to a dict which is "shlex.quote"
    # WORKAROUND: many programming tools failing without shell=true
    # aka: unable to access JAVA_HOME without shell unfortunately, hence mvn command fails
    # see https://stackoverflow.com/questions/28420087/how-to-get-maven-to-work-with-python-subprocess
    process = subprocess.run(
        final_cmd,
        check=False,
        capture_output=True,
        universal_newlines=True,
        encoding="utf-8",
        shell=True,  # nosec # nosemgrep
    )
    process_output = CompletedProcess(process.stdout, process.stderr)
    return process_output


def _raise_exe_not_found(sanitised_command_str: str, error_on_missing_executable: bool = True):
    """
    handle when run command fails with file not found

    :raises EzeExecutableNotFoundError
    """
    core_executable = _extract_executable(sanitised_command_str)
    error_str: str = f"Executable not found '{core_executable}', when running command {sanitised_command_str}"
    if error_on_missing_executable:
        raise EzeExecutableNotFoundError(error_str)
    return CompletedProcess("", error_str)


def _detect_output_errors(
    sanitised_command_str: str, process_output: CompletedProcess, error_on_missing_executable: bool = True
):
    """
    detect errors in process output

    :raises EzeExecutableNotFoundError
    """
    if not error_on_missing_executable:
        return
    is_exe_not_found = _has_missing_exe_output(process_output.stderr) or _has_missing_exe_output(process_output.stdout)
    if is_exe_not_found:
        _raise_exe_not_found(sanitised_command_str, True)


async def run_async_cmd(cmd: list, error_on_missing_executable: bool = True) -> CompletedProcess:
    """
    Supply asyncio.create_subprocess_shell() wrap with additional arguments
    + security: handles shlex parsing of lists to prevent expansion attacks
    + exe not found: handles eze not found error raising EzeExecutableNotFoundError

    :raises EzeExecutableNotFoundError
    """
    sanitised_command_str = __sanitise_command(cmd)
    log_debug(f"running command '{sanitised_command_str}'")

    try:
        process_output = await async_subprocess_run(cmd)
    except FileNotFoundError:
        return _raise_exe_not_found(sanitised_command_str, error_on_missing_executable)
    log_debug(
        f"command '{sanitised_command_str}' std output: '{process_output.stdout}' error output: '{process_output.stderr}'"
    )
    _detect_output_errors(sanitised_command_str, process_output, error_on_missing_executable)
    return process_output


def run_cmd(cmd: list, error_on_missing_executable: bool = True) -> CompletedProcess:
    """
    Supply subprocess.run() wrap with additional arguments
    + security: handles shlex parsing of lists to prevent expansion attacks
    + exe not found: handles eze not found error raising EzeExecutableNotFoundError

    :raises EzeExecutableNotFoundError
    """
    sanitised_command_str = __sanitise_command(cmd)
    log_debug(f"running command '{sanitised_command_str}'")

    try:
        process_output = subprocess_run(cmd)
    except FileNotFoundError:
        return _raise_exe_not_found(sanitised_command_str, error_on_missing_executable)

    log_debug(
        f"command '{sanitised_command_str}' std output: '{process_output.stdout}' error output: '{process_output.stderr}'"
    )
    _detect_output_errors(sanitised_command_str, process_output, error_on_missing_executable)
    return process_output


def __sanitise_command(command_parts: list):
    """Remove secrets from command string"""
    command_str: str = shlex.join(command_parts)
    sanitiser_re = re.compile("--api[ ]+[a-zA-Z0-9-]+")
    sanitised_command_str = re.sub(sanitiser_re, "--api <xxx>", command_str)
    return sanitised_command_str


def detect_pip_command() -> str:
    """Run pip3 and pip to detect which is installed"""
    version = extract_cmd_version(["pip3", "--version"])
    if version:
        return "pip3"
    version = extract_cmd_version(["pip", "--version"])
    if version:
        return "pip"
    # unable to find pip, default to pip
    return "pip"


def detect_pip_executable_version(pip_package: str, cli_command: str) -> str:
    """Run pip for package and check for common version patterns"""
    # 1. detect tool on command line
    # 2. detect version via pip
    #
    # 1. detect if tool on command line
    executable_path = cmd_exists(cli_command)
    if not executable_path:
        return ""
    # 2. detect version via pip, to see what version is installed on cli
    version = extract_version_from_pip(pip_package)
    if not version:
        return "Non-Pip version Installed"
    return version


def extract_version_from_pip(pip_package: str) -> str:
    """Run pip for package and check for common version patterns"""
    pip_command = detect_pip_command()
    return extract_cmd_version([pip_command, "show", pip_package])


def _contains_list_element(text: str, element_list: list = None) -> bool:
    """checks if given text contains list element"""
    if not element_list:
        return False
    for element in element_list:
        if element in text:
            return True
    return False


def extract_cmd_version(command: list, ignored_errors_list: list = None) -> str:
    """
    Run pip for package and check for common version patterns
    """
    completed_process = run_cmd(command, False)
    output = completed_process.stdout
    error_output = completed_process.stderr
    if _has_missing_exe_output(output):
        return ""
    version = _extract_version(output)
    is_acceptable_stderr = not error_output or _contains_list_element(error_output, ignored_errors_list)
    is_valid_version = is_semvar(version) or version != output
    if not is_valid_version or not is_acceptable_stderr:
        version = ""
    return version


def cmd_exists(input_executable: str) -> str:
    """Check if core command exists on path, will return path"""
    return shutil.which(input_executable)


def extract_version_from_maven(mvn_package: str) -> str:
    """
    Take maven package and checks for Maven version
    """
    ignored_errors_list = [
        "WARNING: An illegal reflective access operation has occurred"
    ]
    command: list = ["mvn", "-B", f"-Dplugin={mvn_package}", "help:describe"]
    completed_process = run_cmd(command, False)
    output = completed_process.stdout
    error_output = completed_process.stderr
    if _has_missing_exe_output(output):
        return ""
    version = _extract_maven_version(output)
    is_acceptable_stderr = not error_output or _contains_list_element(error_output, ignored_errors_list)
    if not version or not is_acceptable_stderr:
        version = ""
    return version


def _has_missing_exe_output(output: str) -> bool:
    """Take output and check for exe missing errors"""
    if "is not recognized as an internal or external command" in output:
        return True

    # AOD linux match
    if ": not found" in output:
        return True
    return False


def _extract_version(value: str) -> str:
    """Take output and check for common version patterns"""
    version_matcher = re.compile("[0-9]+[.]([0-9]+[.]?:?)+")
    version_str = re.search(version_matcher, value)
    if version_str:
        return value[version_str.start() : version_str.end()]
    return value


def extract_leading_number(value: str) -> str:
    """Take output and check for common version patterns"""
    leading_number_regex = re.compile("^[0-9.]+")
    leading_number = re.search(leading_number_regex, value)
    if leading_number:
        return value[leading_number.start() : leading_number.end()]
    return ""


def _extract_executable(input_cmd: str) -> str:
    """Take output and check for common executable patterns"""
    leading_cmd_without_args = re.compile("^([a-zA-Z0-9-.]+)")
    output = re.search(leading_cmd_without_args, input_cmd)
    if output:
        return input_cmd[output.start() : output.end()]
    return input_cmd


def _extract_maven_version(value: str) -> str:
    """Take Maven output and checks for version patterns"""
    leading_number_regex = re.compile("Version: ([0-9].[0-9](.[0-9])?)")
    leading_number = re.search(leading_number_regex, value)
    if leading_number is None:
        return ""
    return leading_number.group(1)
