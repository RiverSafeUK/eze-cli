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


# Getting Started

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
- License scanning for violations (aka [strong copyleft](https://en.wikipedia.org/wiki/Copyleft) usage)
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

# Configuring Eze

## Custom configuration
Eze runs off a local **.ezerc.toml** file, when this config is not present, a sample config will be generated automatically by scanning the codebase (`eze test`). You can customise it to:

- Add/remove a scanning tool
- Customise the arguments passed to a specific tool


## Autoconfig **.ezerc.toml**

When **.ezerc.toml** is not present, Eze will auto configure tools according to a "autoconfig.json" file, and generated a **.ezerc.toml** for you

The default autoconfig settings is in "eze/data/default_autoconfig.json"

Can be set to a custom file with ```--autoconfig``` flag

```docker run -t -v FOLDER_TO_SCAN:/data riversafe/eze-cli test --autoconfig PATH ```

### Autoconfig JSON format

```json
{
  "_help_message": "<DEVELOPER COMMENTS>",
  "license": {
    "_help_message": "eze.enums.LicenseScanType value",
    "license_mode": "PROPRIETARY|PERMISSIVE|OPENSOURCE|OFF"
  },
  "tools": {
    "<tool-id>": {
      "_help_message": "<DEVELOPER COMMENTS>",
      "enabled_always": "true or false",
      "enable_on_file": [
        "<LIST OF FILE NAMES IF FOUND WILL ENABLE TOOL>"
      ],
      "enable_on_file_ext": [
        "<LIST OF FILE EXTENSIONS IF FOUND WILL ENABLE TOOL>"
      ],
      "config": {
        "<FIELD>": "<VALUE>"
      }
    }
  },
  "reporters": {
    "<reporter-id>": {
      "_help_message": "LISTED REPORTERS ARE ALWAYS ENABLED",
      "config": {
        "<FIELD>": "<VALUE>"
      }
    }
  }
}
```

### CI Servers: Howto detect Headless Git

Normally when a project is checked out of git, the location can be read from the .git folder.

For CI servers git is check out headlessly (with no .git) and environments are provided for git repo / build number etc, eze will read these environment variables when detecting headless git repos.

These environment variables will need to be feed to eze's docker image.

aka for ado pipeline

```bash
docker run --rm -e "BUILD_SOURCEBRANCHNAME=$BUILD_SOURCEBRANCHNAME" -e "BUILD_REPOSITORY_URI=$BUILD_REPOSITORY_URI" -e "SYSTEM_PULLREQUEST_SOURCEBRANCH=$SYSTEM_PULLREQUEST_SOURCEBRANCH" -v "$(pwd)":/data riversafe/eze-cli test
```

| CI server          | Environment Variables |
| ------------------ | --------------------- |
| ADO                | BUILD_SOURCEBRANCH BUILD_SOURCEBRANCHNAME SYSTEM_PULLREQUEST_SOURCEBRANCH |
| AWS Amplify        | AWS_BRANCH |
| AWS Codebuild      | AWS_BRANCH |
| JENKINS            | GIT_LOCAL_BRANCH GIT_BRANCH |
| IBMCLOUD toolchain | GIT_BRANCH |
| GCP                | BRANCH_NAME |
| Gitlab CI          | CI_COMMIT_BRANCH CI_MERGE_REQUEST_TARGET_BRANCH_NAME CI_EXTERNAL_PULL_REQUEST_TARGET_BRANCH_NAME CI_DEFAULT_BRANCH |
| Github CI          | GITHUB_REF |


## Advanced Configuration: .ezerc.toml

On top of the auto-configuration, you can edit your local **.ezerc.toml** to run custom tools with custom configuration

When a ```.ezerc.toml``` is present, this will be used instead of the autoconfiguration settings

see list of available tools and reporters using these commands

```bash
docker run -t riversafe/eze-cli tools list
docker run -t riversafe/eze-cli tools help <TOOL>
docker run -t riversafe/eze-cli reporters list
docker run -t riversafe/eze-cli reporters help <TOOL>
```

## Advanced Configuration: .ezerc.toml format

## basic .ezerc.toml TOML format

https://en.wikipedia.org/wiki/TOML

```toml
# create template with "docker run -t --rm -v DIRECTORY:/data riversafe/eze-cli housekeeping create-local-config'"

# ===================================
# GLOBAL CONFIG
# ===================================
[global]
# LICENSE_CHECK
LICENSE_CHECK = "PROPRIETARY|PERMISSIVE|OPENSOURCE|OFF"
# LICENSE_ALLOWLIST, list of licenses to exempt from license checks
LICENSE_ALLOWLIST = []
# LICENSE_DENYLIST, list of licenses to always report usage as a error
LICENSE_DENYLIST = []

# ========================================
# TOOL CONFIG
# ========================================
[TOOL_1]
# Full List of Fields and Tool Help available "docker run riversafe/eze-cli tools help <TOOL_NAME>"
TOOL_CONFIG_FIELD = "TOOL_CONFIG_VALUE"

[TOOL_2]
"..." = "..."

# ========================================
# REPORT CONFIG
# ========================================
[REPORTER_1]
# Full List of Fields and Reporter Help available "docker run riversafe/eze-cli reporters help REPORTER_NAME"
REPORTER_CONFIG_FIELD = "REPORTER_CONFIG_VALUE"

[REPORTER_2]
"..." = "..."

# ========================================
# SCAN CONFIG
# ========================================
[scan]
tools = ["TOOL_1","..."]
reporters = ["REPORTER_1", "..."]
```


# Tools and Reporters available

_Updated: 2022/02/08_

## Opensource Tools in Eze


| Type   | Name                 | Version      | License    | Sources                            | Description                                                                           |
| ------ | -------------------- | ------------ | ---------- | ---------------------------------- | ------------------------------------------------------------------------------------- |
| MISC   | raw                  | 0.14.0-alpha | inbuilt    | ALL                                | input for saved eze json reports                                                      |
| SECRET | trufflehog           | 3.0.4        | GPL        | ALL                                | opensource secret scanner                                                             |
| SAST   | semgrep              | 0.81.0       | LGPL       | ALL                                | opensource multi language SAST scanner                                                |
| SCA    | anchore-grype        | 0.32.0       | Apache-2.0 | RUBY,NODE,JAVA,PYTHON,CONTAINER    | opensource multi language SCA and container scanner                                   |
| SBOM   | anchore-syft         | 0.36.0       | Apache-2.0 | RUBY,NODE,JAVA,PYTHON,GO,CONTAINER | opensource multi language and container bill of materials (SBOM) generation utility   |
| SECRET | gitleaks             | 7.5.0        | MIT        | ALL                                | opensource static key scanner                                                         |
| SBOM   | java-cyclonedx       | 2.5.3        | Apache-2.0 | JAVA                               | opensource java bill of materials (SBOM) generation utility                           |
| SCA    | java-dependencycheck | 6.5.3        | Apache-2.0 | JAVA                               | opensource java SCA tool class                                                        |
| SAST   | java-spotbugs        | 4.5.3        | LGPL       | JAVA                               | opensource java SAST tool class                                                       |
| SAST   | python-safety        | 1.10.3       | MIT        | PYTHON                             | opensource python SCA scanner                                                         |
| SCA    | python-piprot        | 0.9.11       | MIT        | PYTHON                             | opensource python outdated dependency scanner                                         |
| SAST   | python-bandit        | 1.7.2        | Apache-2.0 | PYTHON                             | opensource python SAST scanner                                                        |
| SBOM   | python-cyclonedx     | 2.0.1        | Apache-2.0 | PYTHON                             | opensource python bill of materials (SBOM) generation utility, also runs SCA via pypi |
| SCA    | node-npmaudit        | 8.3.1        | NPM        | NODE                               | opensource node SCA scanner                                                           |
| SCA    | node-npmoutdated     | 8.3.1        | NPM        | NODE                               | opensource node outdated dependency scanner                                           |
| SBOM   | node-cyclonedx       | 3.4.0        | Apache-2.0 | NODE                               | opensource node bill of materials (SBOM) generation utility                           |
| SCA    | container-trivy      | 0.18.2       | Apache-2.0 | CONTAINER                          | opensource container scanner                                                          |
| SCA    | kics                 | 1.5.1        | Apache-2.0 | CONTAINER                          | opensource infrastructure scanner                                                     |

An updated list of tools, licenses, and sizes pre-installed in latest Eze Cli Dockerimage can be found using the command

```bash
docker run -t --rm riversafe/eze-cli tools list
docker run -t --rm riversafe/eze-cli tools help <tool-name>
# aka docker run -t --rm riversafe/eze-cli tools help trufflehog
```

## Reporters in Eze

| Name          | Version      | License    | Description                               |
| ------------- | ------------ | ---------- | ----------------------------------------- |
| console       | 0.14.0-alpha | inbuilt    | standard command line reporter            |
| json          | 0.14.0-alpha | inbuilt    | json output file reporter                 |
| s3            | 0.14.0-alpha | inbuilt    | s3 uploader reporter                      |
| junit         | 0.14.0-alpha | inbuilt    | junit output file reporter                |
| quality       | 0.14.0-alpha | inbuilt    | quality gate check reporter               |
| eze           | 0.14.0-alpha | inbuilt    | eze management console reporter           |
| bom           | 0.14.0-alpha | inbuilt    | json cyclonedx bill of materials reporter |
| bom-formatted | 0.15.2       | Apache-2.0 | bill of materials multiformat reporter    |
| sarif         | 0.14.0-alpha | inbuilt    | sarif output file reporter                |
| markdown      | 0.14.0-alpha | inbuilt    | markdown output file formatter            |


An updated list of reporters can be found using the command

```bash
docker run -t --rm riversafe/eze-cli reporters list
docker run -t --rm riversafe/eze-cli reporters help <reporter-name>
# aka docker run -t --rm riversafe/eze-cli reporters help console
```

# Other Common commands

## Stopping a docker image

Started a local eze scan but want to stop the scan without waiting the 30-40 seconds for the scan to complete

To immediately stop a docker image do the following

```bash
# get docker container id
$ docker stats
CONTAINER ID   NAME                 CPU %     MEM USAGE / LIMIT     MEM %     NET I/O          BLOCK I/O   PIDS
f0bef6e0bba7   optimistic_burnell   0.01%     104.8MiB / 12.33GiB   0.83%     221MB / 4.73MB   0B / 0B     17
# docker rm container id
$ docker rm --force f0bef6e0bba7
```

## Asset Caching
Many tools such as maven and npm download depedencies from the internet


### Maven .m2 sharing
Maven can be slow downloading all the artifacts it requires

When you provide a persistent .m2 folder which will speed up scans from 100s to as low as 20s per tool

```bash
# example of sharing your local .m2
docker run -t -v $(pwd -W):/data  -v ~/.m2/:/home/ezeuser/.m2/ eze-cli test
```


# Developers Documentation

To add your own tools checkout [README-DEVELOPMENT.md], this will walk you through installing eze locally for local development.

# Contribute

To start contributing read [CONTRIBUTING.md]

[release]: https://github.com/RiverSafeUK/eze-cli/releases
[release-img]: https://img.shields.io/github/release/RiverSafeUK/eze-cli.svg?logo=github
