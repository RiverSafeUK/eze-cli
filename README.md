![GitHub](https://img.shields.io/github/license/riversafeuk/eze-cli?color=03ac13)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/riversafeuk/eze-cli?label=release&logo=github)
![GitHub All Releases](https://img.shields.io/github/downloads/RiverSafeUK/eze-cli/total?logo=github)
![Docker Pulls](https://img.shields.io/docker/pulls/riversafe/eze-cli?logo=docker)
![PyPI - Downloads](https://img.shields.io/pypi/dm/eze-cli?logo=pypi)

[![Build Status](https://dev.azure.com/riversafe/DevSecOps/_apis/build/status/RiverSafeUK.eze-cli?branchName=develop)](https://dev.azure.com/riversafe/DevSecOps/_build/latest?definitionId=14&branchName=develop)
![GitHub issues](https://img.shields.io/github/issues/riversafeUK/eze-cli?style=flat-square)

# Overview

Eze the one stop solution for security testing in modern development

This tool can be run locally on the cli by developers or security consultants, or deeply integrated into a team / organisations CI pipeline, with team and organisation management dashboards available for reviewing and monitoring the overall security of a organisation's estate.

Features:
- quick setup via Dockerfile with preinstalled tools
- simple multi-tool configuration via a single common configuration file
- normalise multiple tool output into common report format
- extendable plugin architecture for adding new security tools to eze
- provide single cli entrypoint to run the multiple tools needed to test modern applications
- improve uptake of security testing in modern development
- improve discovery and uptake of open source security tools
- extending capabilities of opensource tools
  (adding missing features like ignore patterns, version detection, and cve metadata annotation, as needed)
- layering enterprise level reporting and auditing via the eze management console (PAID service offered by RiverSafe)

# Installation
## Use Locally via Pip
Install eze with pip. Keep in mind that eze runs on Python 3.7 and up.

```bash
pip install eze-cli
```

## Use in Container via Docker
Eze can also be used inside a Docker image, the default Dockerfile contains the eze cli and a selection of common opensource tools out the box.

It's recommended to tailor this Dockerfile, download it and add/remove tools as needed to optimise size of the image.

https://hub.docker.com/r/riversafe/eze-cli

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

# Usage

## Test install

```bash
eze --version
```

```bash
$ eze --version
eze, version X.X.X
```

## Run Eze

- create .ezerc.toml
- run eze
  ```eze test```

## Detect tools locally installed

```bash
eze tools list
```

```bash
$ eze tools list
Available Tools are:
=======================
raw                   0.6.1             input for saved eze json reports
trufflehog            2.0.5             opensource secret scanner
semgrep               0.53.0            opensource multi language SAST scanner
...
```

# Configuring Eze
Eze runs off a local **.ezerc.toml** file, for customising your scans please edit this

When this config is not present, a sample config will be build automatically by scanning the codebase.

## Get Tool Configuration Help

What version if any is installed, and instructions howto install and configure said tool

```bash
eze tools help <TOOL>
```

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

# Developers Documentation

See README-DEVELOPMENT.md

# Contribute

See CONTRIBUTING.md

[release]: https://github.com/RiverSafeUK/eze-cli/releases
[release-img]: https://img.shields.io/github/release/RiverSafeUK/eze-cli.svg?logo=github
