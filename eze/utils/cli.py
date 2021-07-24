"""Basic cli helpers utils

by wrapping the cli tools in a framework, safety execution and santisation of parameters can be achieved
and making sure debugging of command can be achieved without exposing as apikeys/secrets in raw cli command

Open tickets:
# TODO: AB-586: Eze Cli: Enhance security around cli execution, quote all config input
"""

import re
import shutil

# nosec: Subprocess is inheritly required to run cli tools, hence is a neccassary security risk
import subprocess  # nosec

from eze.core.config import EzeConfig


class ExecutableNotFoundException(Exception):
    """Extended exception for missing executable handling"""

    def __init__(self, message: str) -> None:
        """Constructor"""
        super().__init__(message)
        self.message = message


def run_cli_command(cli_config: dict, config: dict, command_name: str) -> subprocess.CompletedProcess:
    """Run tool cli command

    cli_config: dict
        BASE_COMMAND command to start with
        ARGUMENTS list of arguments to add (at start)
        TAIL_ARGUMENTS list of arguments to add (at end)
        FLAGS config-key flag-value pairs

    config: dict
        config-key for FLAGS command
        + inbuilt key ADDITIONAL_ARGUMENTS
    """
    command_str = build_cli_command(cli_config, config)
    completed_process = run_cmd(command_str)

    if EzeConfig.debug_mode:
        print(
            f"""{command_name} ran with output:
    {completed_process.stdout}"""
        )

    if completed_process.stderr:
        sanitised_command_str = __santise_command(command_str)
        print(
            f"""{command_name} ran with warnings/errors:
    Ran: '{sanitised_command_str}'
    Error: {completed_process.stderr}"""
        )
    return completed_process


def _append_to_str(command_str: str, appendees, config: dict) -> str:
    """annonate command string with appendees which are "dict args=config-key kv" or "list of config-keys" """
    for config_key in appendees:
        flag_arg = ""
        if isinstance(appendees, dict):
            flag_arg = appendees[config_key]
        config_value = config.get(config_key, "")
        if config_value:
            # is multiple values
            if isinstance(config_value, list):
                for multi_config_value in config_value:
                    command_str += f" {flag_arg}{multi_config_value}"
            else:
                command_str += f" {flag_arg}{config_value}"
    return command_str


def build_cli_command(cli_config: dict, config: dict) -> str:
    """Build tool cli command

    cli_config: dict
        BASE_COMMAND command to start with
        ARGUMENTS list of arguments to add (at start)
        TAIL_ARGUMENTS list of arguments to add (at end)
        FLAGS config-key flag-value pairs

    config: dict
        config-key for FLAGS command
        + inbuilt key ADDITIONAL_ARGUMENTS
    """
    command_str = cli_config["BASE_COMMAND"]

    argument_keys = cli_config.get("ARGUMENTS", [])
    command_str = _append_to_str(command_str, argument_keys, config)

    argument_keys = cli_config.get("FLAGS", {})
    command_str = _append_to_str(command_str, argument_keys, config)

    argument_keys = cli_config.get("TAIL_ARGUMENTS", {})
    command_str = _append_to_str(command_str, argument_keys, config)

    additional_args = config.get("ADDITIONAL_ARGUMENTS", "")
    if additional_args:
        command_str += f" {additional_args}"
    return command_str


def run_cmd(cmd: str, error_on_missing_executable: bool = True) -> subprocess.CompletedProcess:
    """Supply os.run_cmd() wrap with additional arguments

    throws ExecutableNotFoundException"""
    if not isinstance(cmd, str):
        raise TypeError("invalid cmd type (%s, expected string)" % type(cmd))

    sanitised_command_str = __santise_command(cmd)
    if EzeConfig.debug_mode:
        print(f"running command '{sanitised_command_str}'")

    # nosec: Subprocess with shell=True is inheritly required to run the cli tools, hence is a neccessary security risk
    # TODO: AB-435: Eze Cli: Enhance security around cli execution, quote all config input
    # related enhance build_cli_command to use "shlex.quote" deprecate
    # also map ADDITIONAL_ARGUMENTS to a dict which is "shlex.quote"
    try:
        proc = subprocess.run(cmd, capture_output=True, universal_newlines=True, shell=True)  # nosec # nosemgrep
    except FileNotFoundError:
        core_executable = extract_executable(sanitised_command_str)
        raise ExecutableNotFoundException(
            f"Executable not found '{core_executable}', when running command {sanitised_command_str}"
        )

    if EzeConfig.debug_mode:
        print(f"command '{sanitised_command_str}' std output: '{proc.stdout}' error output: '{proc.stderr}'")

    if error_on_missing_executable and (check_output_corrupt(proc.stderr) or check_output_corrupt(proc.stdout)):
        core_executable = extract_executable(sanitised_command_str)
        raise ExecutableNotFoundException(
            f"Executable not found '{core_executable}', when running command {sanitised_command_str}"
        )
    return proc


def __santise_command(command_str: str):
    """Remove secrets from command string"""
    santiser_re = re.compile("--api[ ]+[a-zA-Z0-9-]+")
    sanitised_command_str = re.sub(santiser_re, "--api <xxx>", command_str)
    return sanitised_command_str


def check_output_corrupt(output: str) -> bool:
    """Take output and check for common errors"""
    if "is not recognized as an internal or external command" in output:
        return True

    # AOD linux match
    if ": not found" in output:
        return True
    return False


def detect_pip_command() -> str:
    """Run pip3 and pip to detect which is installed"""
    version = extract_cmd_version("pip3 --version")
    if version:
        return "pip3"
    version = extract_cmd_version("pip --version")
    if version:
        return "pip"
    return False


def detect_pip_executable_version(pip_package: str, cli_command: str, pip_command: str = "pip") -> str:
    """Run pip for package and check for common version patterns"""
    # 1. detect tool on command line
    # 2. detect version via pip
    #
    # 1. detect if tool on command line
    executable_path = cmd_exists(cli_command)
    if not executable_path:
        return False
    # 2. detect version via pip, to see what version is installed on cli
    version = extract_version_from_pip(pip_package, pip_command)
    if not version:
        return "Non-Pip version Installed"
    return version


def extract_version_from_pip(pip_package: str, pip_command: str = "pip") -> str:
    """Run pip for package and check for common version patterns"""
    return extract_cmd_version(f"""{pip_command} show {pip_package}""")


def extract_cmd_version(command: str) -> str:
    """Run pip for package and check for common version patterns"""
    completed_process = run_cmd(command, False)
    output = completed_process.stdout
    error_output = completed_process.stderr
    if check_output_corrupt(output):
        return ""
    version = extract_version(output)
    if version == output or error_output:
        version = ""
    return version


def extract_version(value: str) -> str:
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


def extract_executable(input_cmd: str) -> str:
    """Take output and check for common executable patterns"""
    leading_cmd_without_args = re.compile("^([a-zA-Z0-9-.]+)")
    output = re.search(leading_cmd_without_args, input_cmd)
    if output:
        return input_cmd[output.start() : output.end()]
    return input_cmd


def cmd_exists(input_executable: str) -> str:
    """Check if core command exists on path, will return path"""
    return shutil.which(input_executable)


def extract_version_from_maven(command: str) -> str:
    """Take output and checks for Maven version"""
    completed_process = run_cmd(command, False)
    output = completed_process.stdout
    error_output = completed_process.stderr
    if check_output_corrupt(output):
        return ""
    version = extract_maven_version(output)
    if version == output or error_output:
        version = ""
    return version


def extract_maven_version(value: str) -> str:
    """Take Maven output and checks for version patterns"""
    leading_number_regex = re.compile("Version: ([0-9].[0-9](.[0-9])?)")
    leading_number = re.search(leading_number_regex, value)
    return leading_number.group(1)
