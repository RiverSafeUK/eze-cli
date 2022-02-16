# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,invalid-name
import shlex
from unittest import mock

import pytest
from pydash import trim

from tests.__test_helpers__.mock_helper import mock_run_cmd
from eze.utils.cli.run import (
    has_missing_exe_output,
    _extract_executable,
    build_cli_command,
    run_cmd,
    EzeExecutableNotFoundError,
    cmd_exists,
    run_cli_command,
    CompletedProcess,
)


def test_is_missing_exe_output__linux_bash_file_missing():
    test_input = """/bin/sh: 1: non-existant.sh: not found\n"""
    output = has_missing_exe_output(test_input)
    assert output is True


def test_is_missing_exe_output__windows_bash_file_missing():
    test_input = """
'safety' is not recognized as an internal or external command,
operable program or batch file."""
    output = has_missing_exe_output(test_input)
    assert output is True


def test_is_missing_exe_output__normal_output():
    test_input = """safety, version 1.10.3"""
    output = has_missing_exe_output(test_input)
    assert output is False


def test_extract_executable__safety_std():
    expected_output = "safety"
    test_input = "safety check --full-report --api=1234 -r something/requirements.txt -r something-else/requirements.txt --json --output /tmp/something-temp something-at end"
    output = _extract_executable(test_input)
    assert output == expected_output


def test_extract_executable__trufflehog_std():
    expected_output = "trufflehog3"
    test_input = "trufflehog3  -f json amplify public src scripts .ezerc.toml package.json -o /tmp/.eze-temp/tmp-truffleHog-report.json --exclude node_modules/.* #current-cloud-backend/.* backend/function/ezemcscanresult/src/node_modules/.* backend/awscloudformation/.*': 'trufflehog3  -f json amplify public src scripts .ezerc package.json -o /tmp/.eze-temp/tmp-truffleHog-report.json --exclude node_modules/.* #current-cloud-backend/.* backend/function/ezemcscanresult/src/node_modules/.* backend/awscloudformation/.*"
    output = _extract_executable(test_input)
    assert output == expected_output


def test_build_command__safety_std():
    expected_output = "safety check --full-report --api=1234 -r something/requirements.txt -r something-else/requirements.txt --json --output /tmp/something-temp something-at end"
    input_cli_config = {
        "BASE_COMMAND": shlex.split("safety check --full-report"),
        "FLAGS": {"APIKEY": "--api=", "REQUIREMENTS_FILES": "-r ", "TEMP_REPORT_FILE": "--json --output "},
    }
    input_config = {
        "APIKEY": "1234",
        "REQUIREMENTS_FILES": ["something/requirements.txt", "something-else/requirements.txt"],
        "ADDITIONAL_ARGUMENTS": "something-at end",
        "TEMP_REPORT_FILE": "/tmp/something-temp",
    }

    output = shlex.join(build_cli_command(input_cli_config, input_config))

    assert output == expected_output


def test_build_command__tail_argument():
    expected_output = "command start --middle=middle end"
    input_cli_config = {
        "BASE_COMMAND": shlex.split("command"),
        "ARGUMENTS": ["START"],
        "TAIL_ARGUMENTS": ["END"],
        "FLAGS": {"MIDDLE": "--middle="},
    }
    input_config = {
        "START": "start",
        "END": "end",
        "MIDDLE": "middle",
    }

    output = shlex.join(build_cli_command(input_cli_config, input_config))

    assert output == expected_output


def test_run_cmd__success():
    # Given
    expected_output_contains = "helloworld"
    expected_error = """"""
    input_cmd = shlex.split("echo 'helloworld'")
    # When
    completed_process = run_cmd(input_cmd, False)
    # Then
    assert expected_output_contains in completed_process.stdout.strip()
    assert completed_process.stderr.strip() == expected_error.strip()


@mock.patch("eze.utils.cli.run.subprocess.run")
@mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=False))
def test_run_cmd__escape_arguments_with_spaces__ab_724_linux(mock_subprocess_run):
    # Given
    expected_command = "some-command --something 'PATH-TO-EXCLUDED-FOLDER/.*' 'some input with spaces'"
    input_cmd = ["some-command", "--something", "PATH-TO-EXCLUDED-FOLDER/.*", "some input with spaces"]
    mock_subprocess_run.reset_mock()
    mock_subprocess_run.side_effect = Exception("Expected Exception")
    # When
    with pytest.raises(Exception) as raised_error:
        run_cmd(input_cmd, False)
    assert raised_error.value.args[0] == "Expected Exception"
    # Then
    cmd_arg = str(mock_subprocess_run.call_args.args[0])
    assert cmd_arg == expected_command


@mock.patch("eze.utils.cli.run.subprocess.run")
@mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=False))
def test_run_cmd__escape_shell_attacks__ab_724_linux(mock_subprocess_run):
    # Given
    expected_command = "some-command --something 'PATH-TO-EXCLUDED-FOLDER/.*' '| /bin/bad-bad-program -i 2>&1'"
    input_cmd = ["some-command", "--something", "PATH-TO-EXCLUDED-FOLDER/.*", "| /bin/bad-bad-program -i 2>&1"]
    mock_subprocess_run.reset_mock()
    mock_subprocess_run.side_effect = Exception("Expected Exception")
    # When
    with pytest.raises(Exception) as raised_error:
        run_cmd(input_cmd, False)
    assert raised_error.value.args[0] == "Expected Exception"
    # Then
    cmd_arg = str(mock_subprocess_run.call_args.args[0])
    assert cmd_arg == expected_command


@mock.patch("eze.utils.cli.run.subprocess.run")
@mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
def test_run_cmd__fixme__ab_724__windows(mock_subprocess_run):
    # Given
    expected_command = 'some-command --something "PATH-TO-EXCLUDED-FOLDER/.*" "some thing with spaces"'
    input_cmd = ["some-command", "--something", "PATH-TO-EXCLUDED-FOLDER/.*", "some thing with spaces"]
    mock_subprocess_run.reset_mock()
    mock_subprocess_run.side_effect = Exception("Expected Exception")
    # When
    with pytest.raises(Exception) as raised_error:
        run_cmd(input_cmd, False)
    assert raised_error.value.args[0] == "Expected Exception"
    # Then
    cmd_arg = str(mock_subprocess_run.call_args.args[0])
    assert cmd_arg == expected_command


# TODO: AB-793: windows should escape detect powershell attacks
# - Powershell expansion attacks
#   PowerShell -Command "temperature | prismcom.exe usb"
@mock.patch("eze.utils.cli.run.subprocess.run")
@mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
def test_run_cmd__fixme__ab_724__windows__Powershell_expansion_attacks(mock_subprocess_run):
    # Given
    expected_command = 'PowerShell -Command "temperature | prismcom.exe usb"'
    input_cmd = ["PowerShell", "-Command", "temperature | prismcom.exe usb"]
    mock_subprocess_run.reset_mock()
    mock_subprocess_run.side_effect = Exception("Expected Exception")
    # When
    with pytest.raises(Exception) as raised_error:
        run_cmd(input_cmd, False)
    assert raised_error.value.args[0] == "Expected Exception"
    # Then
    cmd_arg = str(mock_subprocess_run.call_args.args[0])
    assert cmd_arg == expected_command


def test_run_cmd__failure_no_throw_case():
    # Given
    expected_output = """"""
    expected_windows_error = """'non-existant.sh' is not recognized as an internal or external command,
operable program or batch file."""
    expected_linux_error = "non-existant.sh: not found"

    input_cmd = shlex.split("non-existant.sh some random arguments --api super-secret-apikey")
    # When
    completed_process = run_cmd(input_cmd, False)
    # Then
    assert completed_process.stdout.strip() == expected_output.strip()
    assert (completed_process.stderr.strip() == expected_windows_error.strip()) or (
        expected_linux_error in completed_process.stderr.strip()
    )


def test_run_cmd__failure_throw_case():
    # Given
    expected_error_message = """Executable not found 'non-existant.sh', when running command non-existant.sh some random arguments --api <xxx>"""
    input_cmd = shlex.split("non-existant.sh some random arguments --api super-secret-apikey")
    # When
    with pytest.raises(EzeExecutableNotFoundError) as raised_error:
        run_cmd(input_cmd)
    # Then
    assert raised_error.value.message == expected_error_message


def test_cmd_exists__success():
    # Given
    input_cmd = "echo"
    # When
    output = not not cmd_exists(input_cmd)
    # Then
    assert output is True


def test_cmd_exists__failure():
    # Given
    input_cmd = "non-existant.sh"
    # When
    output = not not cmd_exists(input_cmd)
    # Then
    assert output is False


def test_run_cli_command__sanity():
    expected_output = "helloworld"
    test_input = {"BASE_COMMAND": shlex.split("echo helloworld")}

    completed_process = run_cli_command(test_input)
    output = trim(completed_process.stdout)
    assert output == expected_output
