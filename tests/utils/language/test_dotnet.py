from unittest import mock

import pytest
from eze.core.enums import Vulnerability

from eze.utils.cli.run import CompletedProcess

from tests.__fixtures__.fixture_helper import convert_to_std_object
from eze.utils.language.dotnet import (
    extract_deprecated_packages,
    get_deprecated_packages,
    extract_vulnerable_packages,
    get_vulnerable_packages,
    extract_transitive_packages,
    annotate_transitive_licenses,
)

DEPRECATED_PACKAGE_STDOUT = """
$ dotnet list package --deprecated

The following sources were used:
   https://api.nuget.org/v3/index.json

Project `EzeGoatApp` has the following deprecated packages
   [net6.0]: 
   Top-level Package           Requested   Resolved   Reason(s)   Alternative                      
   > System.Linq.Dynamic       1.0.8       1.0.8      Legacy      System.Linq.Dynamic.Core >= 0.0.0
   > WindowsAzure.Storage      9.3.3       9.3.3      Other       Azure.Storage.Blobs >= 0.0.0
"""

VULNERABLE_PACKAGE_STDOUT = """
$ dotnet list package --vulnerable

The following sources were used:
   https://api.nuget.org/v3/index.json

Project `EzeGoatApp` has the following vulnerable packages
   [net6.0]: 
   Top-level Package      Requested   Resolved   Severity   Advisory URL                                     
   > log4net              2.0.9       2.0.9      Critical   https://github.com/advisories/GHSA-2cwj-8chv-9pp9
"""

TRANSITIVE_PACKAGE_STDOUT = """
$ dotnet list package --include-transitive
Project 'EzeGoatApp' has the following package references
   [net6.0]: 
   Top-level Package                    Requested   Resolved
   > log4net                            2.0.9       2.0.9
   > Microsoft.EntityFrameworkCore      6.0.2       6.0.2
   > System.Linq.Dynamic                1.0.8       1.0.8

   Transitive Package                                                                   Resolved
   > Microsoft.CSharp                                                                   4.3.0
   > Microsoft.EntityFrameworkCore.Abstractions                                         6.0.2
"""


def test_extract_deprecated_packages():
    # Given
    input_stdout = DEPRECATED_PACKAGE_STDOUT
    expected_output = [
        {
            "alternative": "System.Linq.Dynamic.Core >= 0.0.0",
            "installed_version": "1.0.8",
            "package": "System.Linq.Dynamic",
            "reason": "Legacy",
            "request_version": "1.0.8",
        },
        {
            "alternative": "Azure.Storage.Blobs >= 0.0.0",
            "installed_version": "9.3.3",
            "package": "WindowsAzure.Storage",
            "reason": "Other",
            "request_version": "9.3.3",
        },
    ]
    # When
    output = extract_deprecated_packages(input_stdout)
    # Then
    assert convert_to_std_object(output) == expected_output


@pytest.mark.asyncio
@mock.patch("eze.utils.language.dotnet.run_async_cmd")
async def test_get_deprecated_packages(mocked_run_cmd):
    # Given
    input_package = "eze-test-package"
    input_project = "EzeGoatApp.csproj"
    mocked_run_cmd.return_value = CompletedProcess(DEPRECATED_PACKAGE_STDOUT, "")
    expected_output = [
        {
            "confidence": "",
            "file_location": {"line": 1, "path": "EzeGoatApp.csproj"},
            "identifiers": {},
            "is_excluded": False,
            "is_ignored": False,
            "language": "",
            "metadata": None,
            "name": "System.Linq.Dynamic",
            "overview": "'System.Linq.Dynamic' is deprecated",
            "recommendation": "recommended migrate to System.Linq.Dynamic.Core >= 0.0.0",
            "references": [],
            "severity": "medium",
            "version": "1.0.8",
            "vulnerability_type": "dependency",
        },
        {
            "confidence": "",
            "file_location": {"line": 1, "path": "EzeGoatApp.csproj"},
            "identifiers": {},
            "is_excluded": False,
            "is_ignored": False,
            "language": "",
            "metadata": None,
            "name": "WindowsAzure.Storage",
            "overview": "'WindowsAzure.Storage' is deprecated",
            "recommendation": "recommended migrate to Azure.Storage.Blobs >= 0.0.0",
            "references": [],
            "severity": "medium",
            "version": "9.3.3",
            "vulnerability_type": "dependency",
        },
    ]
    # When
    output = await get_deprecated_packages(input_package, input_project)
    # Then
    assert convert_to_std_object(output) == expected_output


def test_extract_vulnerable_packages():
    # Given
    input_stdout = VULNERABLE_PACKAGE_STDOUT
    expected_output = [
        {
            "advisory_id": "GHSA-2cwj-8chv-9pp9",
            "advisory_url": "https://github.com/advisories/GHSA-2cwj-8chv-9pp9",
            "installed_version": "2.0.9",
            "package": "log4net",
            "request_version": "2.0.9",
            "severity": "Critical",
        }
    ]
    # When
    output = extract_vulnerable_packages(input_stdout)
    # Then
    assert convert_to_std_object(output) == expected_output


@pytest.mark.asyncio
@mock.patch("eze.utils.language.dotnet.run_async_cmd")
@mock.patch("eze.utils.language.dotnet.get_osv_id_data")
async def test_get_vulnerable_packages(mocked_get_osv_id_data, mocked_run_cmd):
    # Given
    input_package = "eze-test-package"
    input_project = "EzeGoatApp.csproj"
    mocked_run_cmd.return_value = CompletedProcess(VULNERABLE_PACKAGE_STDOUT, "")
    mocked_get_osv_id_data.return_value = Vulnerability(
        {
            "overview": "mocked osv_id_data",
        }
    )
    expected_output = [
        {
            "confidence": "",
            "file_location": None,
            "identifiers": {},
            "is_excluded": False,
            "is_ignored": False,
            "language": "",
            "metadata": None,
            "name": "",
            "overview": "mocked osv_id_data",
            "recommendation": "",
            "references": [],
            "severity": "",
            "version": "",
            "vulnerability_type": "generic",
        }
    ]
    # When
    output = await get_vulnerable_packages(input_package, input_project)
    # Then
    assert convert_to_std_object(output) == expected_output


def test_extract_transitive_packages():
    # Given
    input_stdout = TRANSITIVE_PACKAGE_STDOUT
    expected_output = {
        "top_level": {
            "Microsoft.EntityFrameworkCore": {
                "installed_version": "6.0.2",
                "is_transitive": False,
                "package": "Microsoft.EntityFrameworkCore",
                "request_version": "6.0.2",
            },
            "System.Linq.Dynamic": {
                "installed_version": "1.0.8",
                "is_transitive": False,
                "package": "System.Linq.Dynamic",
                "request_version": "1.0.8",
            },
            "log4net": {
                "installed_version": "2.0.9",
                "is_transitive": False,
                "package": "log4net",
                "request_version": "2.0.9",
            },
        },
        "transitive": {
            "Microsoft.CSharp": {
                "installed_version": None,
                "is_transitive": True,
                "package": "Microsoft.CSharp",
                "request_version": "4.3.0",
            },
            "Microsoft.EntityFrameworkCore.Abstractions": {
                "installed_version": None,
                "is_transitive": True,
                "package": "Microsoft.EntityFrameworkCore.Abstractions",
                "request_version": "6.0.2",
            },
        },
    }
    # When
    output = extract_transitive_packages(input_stdout)
    # Then
    assert convert_to_std_object(output) == expected_output


@pytest.mark.asyncio
@mock.patch("eze.utils.language.dotnet.run_async_cmd")
async def test_annotate_transitive_licenses(mocked_run_cmd):
    # Given
    input_sbom = {
        "...": "...",
        "metadata": {"...": "..."},
        "components": [
            {"name": "log4net"},
            {"name": "Microsoft.EntityFrameworkCore"},
            {"name": "System.Linq.Dynamic"},
            {"name": "Microsoft.CSharp"},
            {"name": "Microsoft.EntityFrameworkCore.Abstractions"},
        ],
    }
    mocked_run_cmd.return_value = CompletedProcess(TRANSITIVE_PACKAGE_STDOUT, "")
    expected_output = {
        "...": "...",
        "metadata": {"...": "..."},
        "components": [
            {"name": "log4net", "properties": {"transitive": False}},
            {"name": "Microsoft.EntityFrameworkCore", "properties": {"transitive": False}},
            {"name": "System.Linq.Dynamic", "properties": {"transitive": False}},
            {"name": "Microsoft.CSharp", "properties": {"transitive": True}},
            {"name": "Microsoft.EntityFrameworkCore.Abstractions", "properties": {"transitive": True}},
        ],
    }
    # When
    await annotate_transitive_licenses(input_sbom, "some_cwd/")
    # Then
    assert convert_to_std_object(input_sbom) == expected_output
