```

         ______   ______  ______                 _____   _        _____ 
        |  ____| |___  / |  ____|               / ____| | |      |_   _|
        | |__       / /  | |__       ______    | |      | |        | |  
        |  __|     / /   |  __|     |______|   | |      | |        | |  
        | |____   / /__  | |____               | |____  | |____   _| |_ 
        |______| /_____| |______|               \_____| |______| |_____|
```
<p align="center"><strong>The one stop solution for security testing in modern development</strong></p>

![GitHub](https://img.shields.io/github/license/riversafeuk/eze-cli?color=03ac13)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/riversafeuk/eze-cli?label=release&logo=github)
[![Build Status](https://dev.azure.com/riversafe/DevSecOps/_apis/build/status/RiverSafeUK.eze-cli?branchName=develop)](https://dev.azure.com/riversafe/DevSecOps/_build/latest?definitionId=14&branchName=develop)
![GitHub issues](https://img.shields.io/github/issues/riversafeUK/eze-cli?style=rounded-square)
![Docker Pulls](https://img.shields.io/docker/pulls/riversafe/eze-cli?logo=docker)
![PyPI - Downloads](https://img.shields.io/pypi/dm/eze-cli?logo=pypi)


# Overview

Eze is the one stop solution developed by [RiverSafe Ltd](https://riversafe.co.uk/) for security testing in modern development.

Eze cli scans for vulnerable dependencies, insecure code, hardcoded secrets, and license violations across a range of languages

This [docker image](https://hub.docker.com/repository/docker/riversafe/eze-cli) tool orchestrator is designed to be run by developers, security consultants, and ci pipelines

```bash
docker run -t -v FOLDER_TO_SCAN:/data riversafe/eze-cli test
```


**Features**:
- Quick setup via Dockerfile with preinstalled tools
- Auto-configures tools out the box, Supported languages: Python, Node and Java
- SAST tools for finding security anti-patterns 
- SCA tools for finding vulnerable dependencies
- Secret tools for finding hardcoded passwords
- SBOM tools for generating a list of components
- License scanning for violations (aka strong-copyleft usage)
- Extendable plugin architecture for adding new security tools
- Layering enterprise level reporting and auditing via the _Eze Management Console_ (PAID service offered by [RiverSafe](https://riversafe.co.uk/))

# Eze Usage

Just one line, via [docker](https://docs.docker.com/) it'll automatically run the eze scan, and generate a configuration file for tailoring the scan _".ezerc.toml"_

```bash
docker run -t -v FOLDER_TO_SCAN:/data riversafe/eze-cli test
```

_*_ For sysadmin and power users wanting to build their own images, see the [README-DEVELOPMENT.md](README-DEVELOPMENT.md)

## Docker cli shortcuts

These commands will run a security scan against code in the current folder

| CLI                 | Command |
| -----------         | ----------- |
| linux/mac os bash   | ```docker run -t -v "$(pwd)":/data riversafe/eze-cli test```|
| windows git bash    | ```docker run -t -v $(pwd -W):/data riversafe/eze-cli test```|
| windows powershell  | ```docker run -t -v ${PWD}:/data riversafe/eze-cli test```|
| windows cmd         | ```docker run -t -v %cd%:/data riversafe/eze-cli test```|

# Other Common commands

## Detect tools locally installed

```bash
docker run riversafe/eze-cli tools list
```

<details>
<summary>Example</summary>

```
$ eze tools list
Available Tools are:
=======================
raw                   0.6.1             input for saved eze json reports
trufflehog            2.0.5             opensource secret scanner
semgrep               0.53.0            opensource multi language SAST scanner
...
```
</details>


# Configuring Eze

## Custom configuration
Eze runs off a local **.ezerc.toml** file, when this config is not present, a sample config will be generated automatically by scanning the codebase (`eze test`). You can customise it to:

- Add/remove a scanning tool
- Customise the arguments passed to a specific tool

## Get Tool Configuration Help

To show information about a specific tool:
- What version if any is installed.
- Instructions how-to install it and configure

```bash
docker run riversafe/eze-cli tools help <TOOL>
```
<details>
<summary>Result</summary>

```bash
$ docker run riversafe/eze-cli tools help semgrep

Tool 'semgrep' Help
opensource multi language SAST scanner
=================================
Version: 0.52.0 Installed

Tool Configuration Instructions:
=================================
Configuration Format for SemGrep

[semgrep]
...
```
</details>


# Developers Documentation

To add your own tools checkout [README-DEVELOPMENT.md], this will walk you through installing eze locally for local development.

# Contribute

To start contributing read [CONTRIBUTING.md]

[release]: https://github.com/RiverSafeUK/eze-cli/releases
[release-img]: https://img.shields.io/github/release/RiverSafeUK/eze-cli.svg?logo=github
