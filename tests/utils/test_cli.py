# pylint: disable=missing-module-docstring,missing-class-docstring
import pytest

from eze.utils.cli import (
    check_output_corrupt,
    extract_version,
    extract_maven_version,
    build_cli_command,
    extract_executable,
    extract_leading_number,
    run_cmd,
    ExecutableNotFoundException,
    cmd_exists,
)


def test_check_output_corrupt__linux_bash_file_missing():
    input = """/bin/sh: 1: non-existant.sh: not found\n"""
    output = check_output_corrupt(input)
    assert output == True


def test_check_output_corrupt__windows_bash_file_missing():
    input = """
'safetsy' is not recognized as an internal or external command,
operable program or batch file."""
    output = check_output_corrupt(input)
    assert output == True


def test_check_output_corrupt__normal_output():
    input = """safety, version 1.10.3"""
    output = check_output_corrupt(input)
    assert output == False


def test_extract_version__safety_version():
    expected_output = "1.10.3"
    input = """safety, version 1.10.3"""

    output = extract_version(input)
    assert output == expected_output


def test_extract_version__npmaudit_version():
    expected_output = "6.14.11"
    input = """6.14.11"""

    output = extract_version(input)
    assert output == expected_output


def test_extract_version__mvn_version():
    expected_output = "3.8.1"
    input = """Apache Maven 3.8.1 (xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)
Maven home: C:\\dev\\bin\maven\\apache-maven-3.8.1
Java version: 11.0.11, vendor: Amazon.com Inc., runtime: C:\\dev\\bin\\Amazon Corretto\\jdk11.0.11_9
Default locale: en_GB, platform encoding: Cp1252
OS name: "windows 10", version: "10.0", arch: "x86", family: "windows" """

    output = extract_version(input)
    assert output == expected_output


def test_extract_version__truffleHog_version():
    expected_output = "2.2.1"
    input = """Name: truffleHog
Version: 2.2.1
Summary: Searches through git repositories for high entropy strings, digging deep into commit history.
Home-page: https://github.com/dxa4481/truffleHog
Author: Dylan Ayrey
Author-email: dxa4481@rit.edu
License: GNU
Location: c:\\users\\riversafe\\.virtualenvs\\eze-core\\lib\\site-packages
Requires: truffleHogRegexes, GitPython
Required-by:"""
    output = extract_version(input)
    assert output == expected_output


def test_extract_version__bandit_version():
    expected_output = "1.7.0"
    input = """bandit 1.7.0
python version = 3.9.4 (tags/v3.9.4:1f2e308, Apr  6 2021, 13:40:21) [MSC v.1928 64 bit (AMD64)]"""
    output = extract_version(input)
    assert output == expected_output


def test_extract_version__trivy_version():
    expected_output = "0.18.2"
    input = """Version: 0.18.2
Vulnerability DB:
Type: Light
Version: 1
UpdatedAt: 2021-06-03 00:24:48.533715615 +0000 UTC
NextUpdate: 2021-06-03 12:24:48.533715215 +0000 UTC
DownloadedAt: 2021-06-03 10:26:54.4448991 +0000 UTC"""
    output = extract_version(input)
    assert output == expected_output


def test_extract_version__grype_version():
    expected_output = "0.13.0"
    input = """Application:          grype
Version:              0.13.0
BuildDate:            2021-06-02T01:57:12Z
GitCommit:            xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GitTreeState:         clean
Platform:             linux/amd64
GoVersion:            go1.16.4
Compiler:             gc
Supported DB Schema:  3"""
    output = extract_version(input)
    assert output == expected_output


def test_extract_version__gitleaks_version():
    expected_output = "7.5.0"
    input = """v7.5.0"""

    output = extract_version(input)
    assert output == expected_output


def test_extract_executable__safety_std():
    expected_output = "safety"
    input = "safety check --full-report --api=1234 -r something/requirements.txt -r something-else/requirements.txt --json --output /tmp/something-temp something-at end"
    output = extract_executable(input)
    assert output == expected_output


def test_extract_executable__trufflehog_std():
    expected_output = "trufflehog3"
    input = "trufflehog3 --line-numbers -f json amplify public src scripts .ezerc.toml package.json -o /tmp/.eze-temp/tmp-truffleHog-report.json --skip-paths node_modules/.* #current-cloud-backend/.* backend/function/ezemcscanresult/src/node_modules/.* backend/awscloudformation/.*': 'trufflehog3 --line-numbers -f json amplify public src scripts .ezerc package.json -o /tmp/.eze-temp/tmp-truffleHog-report.json --skip-paths node_modules/.* #current-cloud-backend/.* backend/function/ezemcscanresult/src/node_modules/.* backend/awscloudformation/.*"
    output = extract_executable(input)
    assert output == expected_output


def test_extract_version_from_maven__java_spotbugs():
    expected_output = "4.3.0"
    input = """[INFO] Scanning for projects...
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
    output = extract_maven_version(input)
    assert output == expected_output


def test_extract_leading_number__std():
    expected_output = "1.45434"
    input = "1.45434s"
    output = extract_leading_number(input)
    assert output == expected_output


def test_build_command__safety_std():
    expected_output = "safety check --full-report --api=1234 -r something/requirements.txt -r something-else/requirements.txt --json --output /tmp/something-temp something-at end"
    input_cli_config = {
        "BASE_COMMAND": "safety check --full-report",
        "FLAGS": {"APIKEY": "--api=", "REQUIREMENTS_FILES": "-r ", "TEMP_REPORT_FILE": "--json --output "},
    }
    input_config = {
        "APIKEY": "1234",
        "REQUIREMENTS_FILES": ["something/requirements.txt", "something-else/requirements.txt"],
        "ADDITIONAL_ARGUMENTS": "something-at end",
        "TEMP_REPORT_FILE": "/tmp/something-temp",
    }

    output = build_cli_command(input_cli_config, input_config)

    assert output == expected_output


def test_build_command__snyk_std():
    expected_output = (
        "snyk container test debian:stable --file=some-dockerfile/dockerfile --platform=linux --something foo"
    )
    input_cli_config = {
        "BASE_COMMAND": "snyk container test",
        "ARGUMENTS": ["REPOSITORY"],
        "FLAGS": {"DOCKERFILE": "--file=", "PLATFORM": "--platform=", "TEMP_REPORT_FILE": "--json-file-output="},
    }
    input_config = {
        "REPOSITORY": "debian:stable",
        "ADDITIONAL_ARGUMENTS": "--something foo",
        "DOCKERFILE": "some-dockerfile/dockerfile",
        "PLATFORM": "linux",
    }

    output = build_cli_command(input_cli_config, input_config)

    assert output == expected_output


def test_build_command__tail_argument():
    expected_output = "command start --middle=middle end"
    input_cli_config = {
        "BASE_COMMAND": "command",
        "ARGUMENTS": ["START"],
        "TAIL_ARGUMENTS": ["END"],
        "FLAGS": {"MIDDLE": "--middle="},
    }
    input_config = {
        "START": "start",
        "END": "end",
        "MIDDLE": "middle",
    }

    output = build_cli_command(input_cli_config, input_config)

    assert output == expected_output


def test_run_cmd__success():
    # Given
    expected_output_contains = """helloworld"""
    expected_error = """"""
    input_cmd = "echo 'helloworld'"
    # When
    completed_process = run_cmd(input_cmd, False)
    # Then
    assert expected_output_contains in completed_process.stdout.strip()
    assert completed_process.stderr.strip() == expected_error.strip()


def test_run_cmd__failure_no_throw_case():
    # Given
    expected_output = """"""
    expected_windows_error = """'non-existant.sh' is not recognized as an internal or external command,
operable program or batch file."""
    expected_linux_error = "non-existant.sh: not found"

    input_cmd = "non-existant.sh some random arguments --api super-secret-apikey"
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
    input_cmd = "non-existant.sh some random arguments --api super-secret-apikey"
    # When
    with pytest.raises(ExecutableNotFoundException) as thrown_exception:
        completed_process = run_cmd(input_cmd)
    # Then
    assert thrown_exception.value.message == expected_error_message


def test_cmd_exists__success():
    # Given
    input_cmd = "echo"
    # When
    output = not not cmd_exists(input_cmd)
    # Then
    assert output == True


def test_cmd_exists__failure():
    # Given
    input_cmd = "non-existant.sh"
    # When
    output = not not cmd_exists(input_cmd)
    # Then
    assert output == False
