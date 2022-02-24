# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,invalid-name
import shlex
from unittest import mock

from eze.utils.cli.run import CompletedProcess

from tests.__test_helpers__.mock_helper import mock_run_cmd
from eze.utils.cli.version import (
    _extract_version,
    extract_cmd_version,
    cmd_exists,
    extract_version_from_maven,
    _detect_pip_command,
    detect_pip_executable_version,
)


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


@mock.patch("eze.utils.cli.version.run_cmd")
def test_extract_cmd_version__happy_pip(mocked_run_cmd):
    mock_stdout = """pip 21.1.2 from c:\\users\\riversafe\\.pyenv\\pyenv-win\\versions\\3.8.2\\lib\\site-packages\\pip (python 3.8)"""
    expected_output = "21.1.2"
    mocked_run_cmd.return_value = CompletedProcess(mock_stdout)
    output = extract_cmd_version(["pip-something"])
    assert output == expected_output


@mock.patch("eze.utils.cli.version.run_cmd")
def test_extract_cmd_version__full_test_happy(mocked_run_cmd):
    mock_stdout = "0.77.0"
    mock_stderr = "A new version of Semgrep is available. See https://semgrep.dev/docs/upgrading"
    input_ignored_list = ["A new version of Semgrep is available"]
    expected_output = "0.77.0"
    mocked_run_cmd.return_value = CompletedProcess(mock_stdout, mock_stderr)
    output = extract_cmd_version(["some-command"], input_ignored_list)
    assert output == expected_output


@mock.patch("eze.utils.cli.run.run_cmd")
def test_extract_cmd_version__full_test_sad(mocked_run_cmd):
    mock_stdout = "0.77.0"
    mock_stderr = "A new version of Semgrep is available. See https://semgrep.dev/docs/upgrading"
    input_ignored_list = ["nothing"]
    expected_output = ""
    mocked_run_cmd.return_value = CompletedProcess(mock_stdout, mock_stderr)
    output = extract_cmd_version(["some-command"], input_ignored_list)
    assert output == expected_output


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


@mock.patch("eze.utils.cli.version.run_cmd")
def test_extract_version_from_maven_from_maven__ab_720_java_Dependency_Check_no_version_bug(mocked_run_cmd):
    expected_output = "6.5.3"
    mock_stderr = """WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by com.google.inject.internal.cglib.core.$ReflectUtils$1 (file:/usr/share/maven/lib/guice.jar) to method java.lang.ClassLoader.defineClass(java.lang.String,byte[],int,int,java.security.ProtectionDo
main)
WARNING: Please consider reporting this to the maintainers of com.google.inject.internal.cglib.core.$ReflectUtils$1
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release
"""
    mock_stdout = """
[INFO] Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/shared/maven-common-artifact-filters/3.1.0/maven-common-artifact-filters-3.1.0.jar
[INFO] Downloaded from central: https://repo.maven.apache.org/maven2/org/codehaus/plexus/plexus-utils/3.4.1/plexus-utils-3.4.1.jar (264 kB at 53 kB/s)
[INFO] Downloaded from central: https://repo.maven.apache.org/maven2/org/codehaus/plexus/plexus-io/2.0.4/plexus-io-2.0.4.jar (58 kB at 12 kB/s)
[INFO] Downloaded from central: https://repo.maven.apache.org/maven2/org/codehaus/plexus/plexus-archiver/2.2/plexus-archiver-2.2.jar (185 kB at 37 kB/s)
[INFO] Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/shared/maven-common-artifact-filters/3.1.0/maven-common-artifact-filters-3.1.0.jar (61 kB at 12 kB/s)
[INFO] Downloaded from central: https://repo.maven.apache.org/maven2/org/apache/maven/shared/maven-artifact-transfer/0.13.1/maven-artifact-transfer-0.13.1.jar (159 kB at 31 kB/s)
[INFO] org.owasp:dependency-check-maven:6.5.3

Name: Dependency-Check Maven Plugin
Description: dependency-check-maven is a Maven Plugin that uses
  dependency-check-core to detect publicly disclosed vulnerabilities associated
  with the project's dependencies. The plugin will generate a report listing
  the dependency, any identified Common Platform Enumeration (CPE) identifiers,
  and the associated Common Vulnerability and Exposure (CVE) entries.
Group Id: org.owasp
Artifact Id: dependency-check-maven
Version: 6.5.3
Goal Prefix: dependency-check

This plugin has 5 goals:

dependency-check:aggregate
  xxxx

For more information, run 'mvn help:describe [...] -Ddetail'

[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  48.616 s
[INFO] Finished at: 2022-01-18T13:44:53Z
[INFO] ------------------------------------------------------------------------
' error output: 'WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by com.google.inject.internal.cglib.core.$ReflectUtils$1 (file:/usr/share/maven/lib/guice.jar) to method java.lang.ClassLoader.defineClass(java.lang.String,byte[],int,int,java.security.ProtectionDo
main)
WARNING: Please consider reporting this to the maintainers of com.google.inject.internal.cglib.core.$ReflectUtils$1
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release
'
running command 'mvn -B -Dplugin=com.github.spotbugs:spotbugs-maven-plugin help:describe'
"""
    mock_run_cmd(mocked_run_cmd, mock_stdout, mock_stderr)
    output = extract_version_from_maven("some-package")
    assert output == expected_output


@mock.patch("eze.utils.cli.version.run_cmd")
def test_extract_version_from_maven_from_maven__java_spotbugs(mocked_run_cmd):
    expected_output = "4.3.0"
    mock_stdout = """[INFO] Scanning for projects...
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
    mock_run_cmd(mocked_run_cmd, mock_stdout)
    output = extract_version_from_maven("some-package")
    assert output == expected_output


@mock.patch("eze.utils.cli.run.run_cmd")
def test_extract_version_from_maven_from_maven__windows_bash_file_missing(mocked_run_cmd):
    mock_stdout = """
'safety' is not recognized as an internal or external command,
operable program or batch file."""
    mock_run_cmd(mocked_run_cmd, mock_stdout)
    output = extract_version_from_maven("some-package")
    assert output == ""


@mock.patch("eze.utils.cli.run.run_cmd")
def test__detect_pip_command___pip3(mocked_run_cmd):
    mock_stdout = """pip 21.1.2 from c:\\users\\riversafe\\.pyenv\\pyenv-win\\versions\\3.8.2\\lib\\site-packages\\pip (python 3.8)"""
    mock_run_cmd(mocked_run_cmd, mock_stdout)
    output = _detect_pip_command()
    assert output == "pip3"


@mock.patch("eze.utils.cli.version.run_cmd")
def test__detect_pip_command___default_to_pip(mocked_run_cmd):
    mock_stdout = """bash: pipX: command not found"""
    mock_run_cmd(mocked_run_cmd, mock_stdout)
    output = _detect_pip_command()
    assert output == "pip"


@mock.patch("eze.utils.cli.version.cmd_exists", mock.MagicMock(return_value=True))
@mock.patch("eze.utils.cli.version._extract_version_from_pip", mock.MagicMock(return_value="0.8.9"))
def test_detect_pip_executable_version___happy_path_has_version():
    output = detect_pip_executable_version("truffleHog3", "trufflehog3")
    assert output == "0.8.9"


@mock.patch("eze.utils.cli.version.cmd_exists", mock.MagicMock(return_value=False))
@mock.patch("eze.utils.cli.version._extract_version_from_pip", mock.MagicMock(return_value="0.8.9"))
def test_detect_pip_executable_version___unhappy_path_no_executable():
    output = detect_pip_executable_version("truffleHog3", "trufflehog3")
    assert output == ""


@mock.patch("eze.utils.cli.version.cmd_exists", mock.MagicMock(return_value=True))
@mock.patch("eze.utils.cli.version._extract_version_from_pip", mock.MagicMock(return_value=""))
def test_detect_pip_executable_version___unhappy_path_no_pip_install():
    output = detect_pip_executable_version("truffleHog3", "trufflehog3")
    assert output == "Non-Pip version Installed"
