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

Eze is the one stop solution for security testing in modern development.

This tool can be run locally on the cli by developers or security consultants, or deeply integrated into a team / organisations CI pipeline, with team and organisation management dashboards available for reviewing and monitoring the overall security of a organisation's estate.

**Features**:
- Quick setup via Dockerfile with preinstalled tools
- Simple multi-tool configuration via a single common configuration file
  - Support for multiple targets: remote git repositories, containers
  - Supports Python, Node and Java applications.
- Run multiple tools with one command
- Extendable plugin architecture for adding new security tools
- Improve uptake of security testing in modern development.
- Improve discovery and uptake of open source security tools
- Extends capabilities of raw opensource tools underneath
  (adding missing features like ignore patterns, version detection, and cve metadata annotation, as needed)
- Layering enterprise level reporting and auditing via the _Eze Management Console_ (PAID service offered by RiverSafe)


# Eze Usage

It is **strongly*** recommended most users run eze inside the docker image, this is the easiest way to get started with eze security scanning.

_*_ For sysadmin and power users, see the [README-DEVELOPMENT.md](README-DEVELOPMENT.md)


## Pull Docker image
Eze is inside this [Docker image](https://hub.docker.com/r/riversafe/eze-cli), the default Dockerfile contains the `eze cli` running inside a default linux os with a selection of opensource security tools out of the box.

```bash
# Pull docker image
docker pull riversafe/eze-cli:latest

# Test docker running ok
docker run riversafe/eze-cli --version
```


## Run security scan

This command will run a security scan against the current folder. Results will be in eze_report.json

```bash
# Scan code in current directory (cmd)
docker run --rm -v %cd%:/data riversafe/eze-cli test

# Scan code in current directory (powershell)
docker run --rm -v ${PWD}:/data riversafe/eze-cli test

# Scan code in current directory (git bash)
docker run --rm -v $(pwd -W):/data riversafe/eze-cli test

# Scan code in current directory (linux/mac os bash)
docker run --rm -v "$(pwd)":/data riversafe/eze-cli test
```

_*For advanced users this Dockerfile image can be downloaded and tailored to optimise the size of the image / versions of tools._


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
