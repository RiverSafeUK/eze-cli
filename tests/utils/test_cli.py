# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,invalid-name
import shlex
from unittest import mock

import pytest
from pydash import trim

from tests.__test_helpers__.mock_helper import mock_run_cmd
from eze.utils.cli import (
    _check_output_corrupt,
    _extract_version,
    _extract_executable,
    build_cli_command,
    extract_leading_number,
    run_cmd,
    EzeExecutableNotFoundError,
    cmd_exists,
    run_cli_command,
    extract_version_from_maven,
    detect_pip_command,
    detect_pip_executable_version,
)


def test_check_output_corrupt__linux_bash_file_missing():
    test_input = """/bin/sh: 1: non-existant.sh: not found\n"""
    output = _check_output_corrupt(test_input)
    assert output is True


def test_check_output_corrupt__windows_bash_file_missing():
    test_input = """
'safety' is not recognized as an internal or external command,
operable program or batch file."""
    output = _check_output_corrupt(test_input)
    assert output is True


def test_check_output_corrupt__normal_output():
    test_input = """safety, version 1.10.3"""
    output = _check_output_corrupt(test_input)
    assert output is False


def test_extract_version__safety_version():
    expected_output = "1.10.3"
    test_input = """safety, version 1.10.3"""

    output = _extract_version(test_input)
    assert output == expected_output


def test_extract_version__npmaudit_version():
    expected_output = "6.14.11"
    test_input = """6.14.11"""

    output = _extract_version(test_input)
    assert output == expected_output


def test_extract_version__mvn_version():
    expected_output = "3.8.1"
    test_input = """Apache Maven 3.8.1 (xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)
Maven home: C:\\dev\\bin\\maven\\apache-maven-3.8.1
Java version: 11.0.11, vendor: Amazon.com Inc., runtime: C:\\dev\\bin\\Amazon Corretto\\jdk11.0.11_9
Default locale: en_GB, platform encoding: Cp1252
OS name: "windows 10", version: "10.0", arch: "x86", family: "windows" """

    output = _extract_version(test_input)
    assert output == expected_output


def test_extract_version__truffleHog_version():
    expected_output = "2.2.1"
    test_input = """Name: truffleHog
Version: 2.2.1
Summary: Searches through git repositories for high entropy strings, digging deep into commit history.
Home-page: https://github.com/dxa4481/truffleHog
Author: Dylan Ayrey
Author-email: dxa4481@rit.edu
License: GNU
Location: c:\\users\\riversafe\\.virtualenvs\\eze-core\\lib\\site-packages
Requires: truffleHogRegexes, GitPython
Required-by:"""
    output = _extract_version(test_input)
    assert output == expected_output


def test_extract_version__bandit_version():
    expected_output = "1.7.0"
    test_input = """bandit 1.7.0
python version = 3.9.4 (tags/v3.9.4:1f2e308, Apr  6 2021, 13:40:21) [MSC v.1928 64 bit (AMD64)]"""
    output = _extract_version(test_input)
    assert output == expected_output


def test_extract_version__trivy_version():
    expected_output = "0.18.2"
    test_input = """Version: 0.18.2
Vulnerability DB:
Type: Light
Version: 1
UpdatedAt: 2021-06-03 00:24:48.533715615 +0000 UTC
NextUpdate: 2021-06-03 12:24:48.533715215 +0000 UTC
DownloadedAt: 2021-06-03 10:26:54.4448991 +0000 UTC"""
    output = _extract_version(test_input)
    assert output == expected_output


def test_extract_version__grype_version():
    expected_output = "0.13.0"
    test_input = """Application:          grype
Version:              0.13.0
BuildDate:            2021-06-02T01:57:12Z
GitCommit:            xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GitTreeState:         clean
Platform:             linux/amd64
GoVersion:            go1.16.4
Compiler:             gc
Supported DB Schema:  3"""
    output = _extract_version(test_input)
    assert output == expected_output


def test_extract_version__gitleaks_version():
    expected_output = "7.5.0"
    test_input = """v7.5.0"""

    output = _extract_version(test_input)
    assert output == expected_output


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


def test_extract_leading_number__std():
    expected_output = "1.45434"
    test_input = "1.45434s"
    output = extract_leading_number(test_input)
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
    expected_output_contains = """helloworld"""
    expected_error = """"""
    input_cmd = shlex.split("echo 'helloworld'")
    # When
    completed_process = run_cmd(input_cmd, False)
    # Then
    assert expected_output_contains in completed_process.stdout.strip()
    assert completed_process.stderr.strip() == expected_error.strip()


@mock.patch("eze.utils.cli.subprocess.run")
@mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=False))
def test_run_cmd__escape_arguments_with_spaces__ab_724_linux(mock_subprocess_run):
    # Given
    expected_command = "some-command --something 'PATH-TO-EXCLUDED-FOLDER/.*' 'some input with spaces'"
    input_cmd = ["some-command", "--something", "PATH-TO-EXCLUDED-FOLDER/.*", "some input with spaces"]
    mock_subprocess_run.reset_mock()
    mock_subprocess_run.side_effect = Exception("Expected Exception")
    # When
    try:
        run_cmd(input_cmd, False)
    except Exception as err:
        assert err.args[0] == "Expected Exception"
    # Then
    cmd_arg = str(mock_subprocess_run.call_args.args[0])
    assert cmd_arg == expected_command


@mock.patch("eze.utils.cli.subprocess.run")
@mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=False))
def test_run_cmd__escape_shell_attacks__ab_724_linux(mock_subprocess_run):
    # Given
    expected_command = "some-command --something 'PATH-TO-EXCLUDED-FOLDER/.*' '| /bin/bad-bad-program -i 2>&1'"
    input_cmd = ["some-command", "--something", "PATH-TO-EXCLUDED-FOLDER/.*", "| /bin/bad-bad-program -i 2>&1"]
    mock_subprocess_run.reset_mock()
    mock_subprocess_run.side_effect = Exception("Expected Exception")
    # When
    try:
        run_cmd(input_cmd, False)
    except Exception as err:
        assert err.args[0] == "Expected Exception"
    # Then
    cmd_arg = str(mock_subprocess_run.call_args.args[0])
    assert cmd_arg == expected_command


@mock.patch("eze.utils.cli.subprocess.run")
@mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
def test_run_cmd__fixme__ab_724__windows(mock_subprocess_run):
    # Given
    expected_command = 'some-command --something "PATH-TO-EXCLUDED-FOLDER/.*" "some thing with spaces"'
    input_cmd = ["some-command", "--something", "PATH-TO-EXCLUDED-FOLDER/.*", "some thing with spaces"]
    mock_subprocess_run.reset_mock()
    mock_subprocess_run.side_effect = Exception("Expected Exception")
    # When
    try:
        run_cmd(input_cmd, False)
    except Exception as err:
        assert err.args[0] == "Expected Exception"
    # Then
    cmd_arg = str(mock_subprocess_run.call_args.args[0])
    assert cmd_arg == expected_command


# TODO: AB-793: windows should escape detect powershell attacks
# - Powershell expansion attacks
#   PowerShell -Command "temperature | prismcom.exe usb"
@mock.patch("eze.utils.cli.subprocess.run")
@mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
def test_run_cmd__fixme__ab_724__windows__Powershell_expansion_attacks(mock_subprocess_run):
    # Given
    expected_command = 'PowerShell -Command "temperature | prismcom.exe usb"'
    input_cmd = ["PowerShell", "-Command", "temperature | prismcom.exe usb"]
    mock_subprocess_run.reset_mock()
    mock_subprocess_run.side_effect = Exception("Expected Exception")
    # When
    try:
        run_cmd(input_cmd, False)
    except Exception as err:
        assert err.args[0] == "Expected Exception"
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
    with pytest.raises(EzeExecutableNotFoundError) as thrown_exception:
        run_cmd(input_cmd)
    # Then
    assert thrown_exception.value.message == expected_error_message


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


@mock.patch("eze.utils.cli.run_cmd")
def test_extract_version_from_maven_from_maven__java_spotbugs(mocked_run_cmd):
    expected_output = "4.3.0"
    test_input = """[INFO] Scanning for projects...
[INFO] 
[INFO] ------------------< org.apache.maven:standalone-pom >-------------------
[INFO] Building Maven Stub Project (No POM) 1
[INFO] --------------------------------[ pom ]---------------------------------
[INFO] 
[INFO] --- maven-help-plugin:3.2.0:describe (default-cli) @ standalone-pom ---
[INFO] com.github.spotbugs:spotbugs-maven-plugin:4.3.0

Name: SpotBugs Maven Plugin
Description: This Plug-In generates reports based on the SpotBugs Library
Group Id: com.github.spotbugs
Artifact Id: spotbugs-maven-plugin
Version: 4.3.0
Goal Prefix: spotbugs

This plugin has 4 goals:

spotbugs:check
  Description: (no description available)

spotbugs:gui
  Description: (no description available)

spotbugs:help
  Description: Display help information on spotbugs-maven-plugin.
    Call mvn spotbugs:help -Ddetail=true -Dgoal=<goal-name> to display
    parameter details.

spotbugs:spotbugs
  Description: (no description available)
  Note: This goal should be used as a Maven report.

For more information, run 'mvn help:describe [...] -Ddetail'

[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  2.355 s
[INFO] Finished at: 2021-07-19T14:29:37+01:00
[INFO] ------------------------------------------------------------------------"""
    mock_run_cmd(mocked_run_cmd, test_input)
    output = extract_version_from_maven("some-package")
    assert output == expected_output


@mock.patch("eze.utils.cli.run_cmd")
def test_extract_version_from_maven_from_maven__windows_bash_file_missing(mocked_run_cmd):
    test_input = """
'safety' is not recognized as an internal or external command,
operable program or batch file."""
    mock_run_cmd(mocked_run_cmd, test_input)
    output = extract_version_from_maven("some-package")
    assert output == ""


@mock.patch("eze.utils.cli.run_cmd")
def test_detect_pip_command___pip3(mocked_run_cmd):
    test_input = """pip 21.1.2 from c:\\users\\riversafe\\.pyenv\\pyenv-win\\versions\\3.8.2\\lib\\site-packages\\pip (python 3.8)"""
    mock_run_cmd(mocked_run_cmd, test_input)
    output = detect_pip_command()
    assert output == "pip3"


@mock.patch("eze.utils.cli.run_cmd")
def test_detect_pip_command___default_to_pip(mocked_run_cmd):
    test_input = """bash: pipX: command not found"""
    mock_run_cmd(mocked_run_cmd, test_input)
    output = detect_pip_command()
    assert output == "pip"


@mock.patch("eze.utils.cli.cmd_exists", mock.MagicMock(return_value=True))
@mock.patch("eze.utils.cli.extract_version_from_pip", mock.MagicMock(return_value="0.8.9"))
def test_detect_pip_executable_version___happy_path_has_version():
    output = detect_pip_executable_version("truffleHog3", "trufflehog3")
    assert output == "0.8.9"


@mock.patch("eze.utils.cli.cmd_exists", mock.MagicMock(return_value=False))
@mock.patch("eze.utils.cli.extract_version_from_pip", mock.MagicMock(return_value="0.8.9"))
def test_detect_pip_executable_version___unhappy_path_no_executable():
    output = detect_pip_executable_version("truffleHog3", "trufflehog3")
    assert output == ""


@mock.patch("eze.utils.cli.cmd_exists", mock.MagicMock(return_value=True))
@mock.patch("eze.utils.cli.extract_version_from_pip", mock.MagicMock(return_value=""))
def test_detect_pip_executable_version___unhappy_path_no_pip_install():
    output = detect_pip_executable_version("truffleHog3", "trufflehog3")
    assert output == "Non-Pip version Installed"
