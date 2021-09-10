<h1 align="center"><strong>EZE</strong></h1>
<p align="center">The one stop solution for security testing in modern development</p>

![GitHub](https://img.shields.io/github/license/riversafeuk/eze-cli?color=03ac13)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/riversafeuk/eze-cli?label=release&logo=github)
![GitHub All Releases](https://img.shields.io/github/downloads/RiverSafeUK/eze-cli/total?logo=github)
![Docker Pulls](https://img.shields.io/docker/pulls/riversafe/eze-cli?logo=docker)
![PyPI - Downloads](https://img.shields.io/pypi/dm/eze-cli?logo=pypi)
[![Build Status](https://dev.azure.com/riversafe/DevSecOps/_apis/build/status/RiverSafeUK.eze-cli?branchName=develop)](https://dev.azure.com/riversafe/DevSecOps/_build/latest?definitionId=14&branchName=develop)
![GitHub issues](https://img.shields.io/github/issues/riversafeUK/eze-cli?style=flat-square)


# Overview

Eze is the one stop solution for security testing in modern development.

This tool can be run locally on the cli by developers or security consultants, or deeply integrated into a team / organisations CI pipeline, with team and organisation management dashboards available for reviewing and monitoring the overall security of a organisation's estate.

**Features**:
- Quick setup via Dockerfile with preinstalled tools
- Simple multi-tool configuration via a single common configuration file
  - Support for multiple targets: remote git repositories, containers
  - Supports Python, Node and Java applications.
- Normalise multiple tools output into one common report format
- Extendable plugin architecture for adding new security tools to Eze
- Provide single cli entrypoint to run the multiple tools needed to test modern applications
- Improve uptake of security testing in modern development.
- Improve discovery and uptake of open source security tools
- Extending capabilities of opensource tools
  (adding missing features like ignore patterns, version detection, and cve metadata annotation, as needed)
- Layering enterprise level reporting and auditing via the _Eze Management Console_ (PAID service offered by RiverSafe)


# Installation and Usage
## Use Eze Locally via Pip
Install Eze from Pypi using pip. 

```bash
# Keep in mind that Eze runs on Python 3.7 and up.
pip install eze-cli

# Test Eze running ok
eze, version X.X.X
```
Once finished, you can install any tools you want to run Eze with. And  run Eze inside your directory.
```bash
eze test
```

<details>
<summary>Example: Scanning a Python project using  Eze</summary>

```py
# Install 3 tools and run Eze
pip install piprot
pip install bandit
pip install safety
eze test
```
</details>


## Use Eze in Container via Docker
Eze can also be used without installation with a [Docker image](https://hub.docker.com/r/riversafe/eze-cli), the default Dockerfile contains the `eze cli` and a selection of common opensource tools out of the box.

It's recommended to tailor this Dockerfile, download it and add/remove tools as needed to optimise the size of the image.


```bash
# Pull docker image
docker pull riversafe/eze-cli:latest

# Test docker running ok
docker run riversafe/eze-cli --version

# Run pulled image in docker (cmd)
docker run --rm -v %cd%:/data riversafe/eze-cli test

# Run pulled image in (powershell)
docker run --rm -v ${PWD}:/data riversafe/eze-cli test

# Run pulled image in (git bash)
docker run --rm -v $(pwd -W):/data riversafe/eze-cli test

# Run pulled image in (linux/mac os bash)
docker run --rm -v "$(pwd)":/data riversafe/eze-cli test
```

# Additional commands

## Detect tools locally installed

```bash
eze tools list
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


## Scan a remote repository

```bash
eze test-remote --url <remote_uri> --branch <branch_name>
```

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
eze tools help <TOOL>
```
<details>
<summary>Result</summary>

```bash
$ eze tools help semgrep

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
</br>


# Developers Documentation

To add your own tools check README-DEVELOPMENT.md

# Contribute

To start contributing read CONTRIBUTING.md

[release]: https://github.com/RiverSafeUK/eze-cli/releases
[release-img]: https://img.shields.io/github/release/RiverSafeUK/eze-cli.svg?logo=github
