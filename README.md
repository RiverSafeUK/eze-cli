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

_add -t to docker to enable terminal colours_

```bash
docker run -t -v FOLDER_TO_SCAN:/data riversafe/eze-cli test
```

_*_ For sysadmin and power users wanting to build their own images, see the [README-DEVELOPMENT.md](README-DEVELOPMENT.md)

## Docker cli shortcuts

These commands will run a security scan against code in the current folder

| CLI                 | Command |
| -----------         | ----------- |
| linux/mac os bash   | ```docker run -t -v "$(pwd)":/data riversafe/eze-cli test```|
| windows git bash    | ```docker run -t -e "WINDOWS_DOCKER_WORKAROUND=true" -v $(pwd -W):/data riversafe/eze-cli test```|
| windows powershell  | ```docker run -t -e "WINDOWS_DOCKER_WORKAROUND=true" -v ${PWD}:/data riversafe/eze-cli test```|
| windows cmd         | ```docker run -t -e "WINDOWS_DOCKER_WORKAROUND=true" -v %cd%:/data riversafe/eze-cli test```|

### Running Eze Docker Image on Windows

Windows mounted volumes are extremely slow, you can add the environment varibale "WINDOWS_DOCKER_WORKAROUND" to fix this

Eze will copy code to /tmp on the image for scanning, stores files inside TMP/.eze/

This will speed up windows scan be as much as 80%

```bash
docker run -t -e "WINDOWS_DOCKER_WORKAROUND=true" -v FOLDER_TO_SCAN:/data riversafe/eze-cli test
```

# Other Common commands

## Detect tools locally installed

```bash
docker run -t riversafe/eze-cli tools list
```

```
$ eze tools list
Available Tools are:
=======================
raw                   0.6.1             input for saved eze json reports
trufflehog            2.0.5             opensource secret scanner
semgrep               0.53.0            opensource multi language SAST scanner
...
```

## Stopping a docker image

Started an eze scan but want to stop the scan without waiting the 30-40 seconds for the scan to complete

To immediately stop a docker image do the following

```bash
# get docker container id
$ docker stats
CONTAINER ID   NAME                 CPU %     MEM USAGE / LIMIT     MEM %     NET I/O          BLOCK I/O   PIDS
f0bef6e0bba7   optimistic_burnell   0.01%     104.8MiB / 12.33GiB   0.83%     221MB / 4.73MB   0B / 0B     17
# docker rm container id
$ docker rm --force f0bef6e0bba7
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
docker run -t riversafe/eze-cli tools help <TOOL>
```
<details>
<summary>Result</summary>

```bash
$ docker run -t riversafe/eze-cli tools help semgrep

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



# Opensource Tools in Eze

| Type   | Name                 | Version      | License    | Description                                                                         |
| ------ | -------------------- | ------------ | ---------- | ----------------------------------------------------------------------------------- |
| MISC   | raw                  | 0.12.0-alpha | inbuilt    | input for saved eze json reports                                                    |
| SECRET | trufflehog           | 3.0.4        | GNU        | opensource secret scanner                                                           |
| SAST   | semgrep              | 0.77.0       | LGPL       | opensource multi language SAST scanner                                              |
| SCA    | anchore-grype        | 0.28.0       | Apache-2.0 | opensource multi language SCA and container scanner                                 |
| SBOM   | anchore-syft         | 0.34.0       | Apache-2.0 | opensource multi language and container bill of materials (SBOM) generation utility |
| SECRET | gitleaks             | 7.5.0        | MIT        | opensource static key scanner                                                       |
| SBOM   | java-cyclonedx       | 2.5.3        | Apache-2.0 | opensource java bill of materials (SBOM) generation utility                         |
| SCA    | java-dependencycheck | 6.5.3        | Apache-2.0 | opensource java SCA tool class                                                      |
| SAST   | java-spotbugs        | 4.5.3        | LGPL       | opensource java SAST tool class                                                     |
| SAST   | python-safety        | 1.10.3       | MIT        | opensource python SCA scanner                                                       |
| SCA    | python-piprot        | 0.9.11       | MIT        | opensource python outdated dependency scanner                                       |
| SAST   | python-bandit        | 1.7.1        | Apache-2.0 | opensource python SAST scanner                                                      |
| SBOM   | python-cyclonedx     | 1.5.3        | Apache-2.0 | opensource python bill of materials (SBOM) generation utility                       |
| SCA    | node-npmaudit        | 8.3.0        | NPM        | opensource node SCA scanner                                                         |
| SCA    | node-npmoutdated     | 8.3.0        | NPM        | opensource node outdated dependency scanner                                         |
| SBOM   | node-cyclonedx       | 3.3.1        | Apache-2.0 | opensource node bill of materials (SBOM) generation utility                         |
| SCA    | container-trivy      | 0.18.2       | Apache-2.0 | opensource container scanner                                                        |
| SCA    | kics                 | 1.4.9        | Apache-2.0 | opensource infrastructure scanner                                                   |

_Updated: 18/01/2022_

An updated list of tools, licenses, and sizes pre-installed in latest Eze Cli Dockerimage can be found using the command

```bash
docker run -t --rm riversafe/eze-cli tools list --include-source-type
docker run -t --rm riversafe/eze-cli tools help <tool-name>
# aka docker run -t --rm riversafe/eze-cli tools help trufflehog
```

# Reporters in Eze

| Name          | Version      | License    | Description                            |
| ------------- | ------------ | ---------- | -------------------------------------- |
| console       | 0.12.0-alpha | inbuilt    | standard command line reporter         |
| json          | 0.12.0-alpha | inbuilt    | json output file reporter              |
| s3            | 0.12.0-alpha | inbuilt    | s3 uploader reporter                   |
| junit         | 0.12.0-alpha | inbuilt    | junit output file reporter             |
| quality       | 0.12.0-alpha | inbuilt    | quality gate check reporter            |
| eze           | 0.12.0-alpha | inbuilt    | eze management console reporter        |
| bom           | 0.12.0-alpha | inbuilt    | json dx bill of materials reporter     |
| bom-formatted | 0.15.2       | Apache-2.0 | bill of materials multiformat reporter |
| sarif         | 0.12.0-alpha | inbuilt    | sarif output file reporter             |

_Updated: 18/01/2022_

An updated list of reporters can be found using the command

```bash
docker run -t --rm riversafe/eze-cli reporters list --include-source-type
docker run -t --rm riversafe/eze-cli reporters help <reporter-name>
# aka docker run -t --rm riversafe/eze-cli reporters help console
```

# Developers Documentation

To add your own tools checkout [README-DEVELOPMENT.md], this will walk you through installing eze locally for local development.

# Contribute

To start contributing read [CONTRIBUTING.md]

[release]: https://github.com/RiverSafeUK/eze-cli/releases
[release-img]: https://img.shields.io/github/release/RiverSafeUK/eze-cli.svg?logo=github
