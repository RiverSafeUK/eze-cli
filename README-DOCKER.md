Eze the one stop solution for security testing in modern development

The default eze-cli Dockerfile contains the eze cli, and a selection of common opensource tools out the box.

# How to Run Eze in Docker

Simple usage, mount your codebase into volume **/data**, then run docker with "test" argument

```bash
# 1) Pull docker image
docker pull riversafe/eze-cli:latest

# 2) [in cmd] Run pulled image in docker
docker run -t --rm -v %cd%:/data riversafe/eze-cli test

# 2) [in powershell] Run pulled image in docker
docker run -t --rm -v ${PWD}:/data riversafe/eze-cli test

# 2) [in git bash] Run pulled image in docker
docker run -t --rm -v $(pwd -W):/data riversafe/eze-cli test

# 2) [in linux/mac os bash] Run pulled image in docker
docker run -t --rm -v "$(pwd)":/data riversafe/eze-cli test
```

# Configuring Eze
Eze runs off a local **.ezerc.toml** file, for customising your scans please edit this

When this config is not present, a sample config will be build automatically by scanning the codebase.

More information available on github:
https://github.com/RiverSafeUK/eze-cli

# Tools Installed
List of tools, licenses, and sizes pre-installed in latest Eze Cli Dockerimage can be found using the command

```bash
docker run -t --rm riversafe/eze-cli tools list --include-source-type
docker run -t --rm riversafe/eze-cli tools help <tool-name>
aka docker run -t --rm riversafe/eze-cli tools help trufflehog
```

_Updated: 26/07/2021_
```bash
 | Type   | Name                 | Version       | License    | Sources                             | Description                                                                         |
*|********|**********************|***************|************|*************************************|*************************************************************************************|*
 | SECRET | trufflehog           | 2.0.6         | GNU        | ALL                                 | opensource secret scanner                                                           |
 | SAST   | semgrep              | 0.59.0        | LGPL       | ALL                                 | opensource multi language SAST scanner                                              |
 | SCA    | anchore-grype        | 0.15.0        | Apache 2.0 | RUBY,NODE,JAVA,PYTHON,CONTAINER     | opensource multi language SCA and container scanner                                 |
 | SBOM   | anchore-syft         | 0.19.1        | Apache 2.0 | RUBY,NODE,JAVA,PYTHON,GO,CONTAINER  | opensource multi language and container bill of materials (SBOM) generation utility |
 | SECRET | gitleaks             | 7.5.0         | MIT        | ALL                                 | opensource static key scanner                                                       |
 | SBOM   | java-cyclonedx       | 2.5.1         | Apache 2.0 | JAVA                                | opensource java bill of materials (SBOM) generation utility                         |
 | SCA    | java-dependencycheck | 6.2.2         | Apache 2.0 | JAVA                                | opensource java SCA tool class                                                      |
 | SAST   | java-spotbugs        | 4.3.0         | LGPL       | JAVA                                | opensource java SAST tool class                                                     |
 | SAST   | python-safety        | 1.10.3        | MIT        | PYTHON                              | opensource python SCA scanner                                                       |
 | SCA    | python-piprot        | 0.9.11        | MIT        | PYTHON                              | opensource python outdated dependency scanner                                       |
 | SAST   | python-bandit        | 1.7.0         | Apache 2.0 | PYTHON                              | opensource python SAST scanner                                                      |
 | SBOM   | python-cyclonedx     | 0.4.3         | Apache 2.0 | PYTHON                              | opensource python bill of materials (SBOM) generation utility                       |
 | SCA    | node-npmaudit        | 7.18.1        | NPM        | NODE                                | opensource node SCA scanner                                                         |
 | SCA    | node-npmoutdated     | 7.18.1        | NPM        | NODE                                | opensource node outdated dependency scanner                                         |
 | SBOM   | node-cyclonedx       | 3.0.3         | Apache 2.0 | NODE                                | opensource node bill of materials (SBOM) generation utility                         |
 | SCA    | container-trivy      | 0.18.2        | Apache 2.0 | CONTAINER                           | opensource container scanner                                                        |
```

# Tailoring Image
It's recommended for organisations with mature devops teams to download and tailor this Docker image, adding/removing the pre-installed security tools as needed to optimise size of the image, as well as making their own **.ezerc.toml** files.

_*Aka: Some tools for example semgrep are upto 200mb by themselves, tailoring the image to remove unused tools will save significant amounts of space_

Dockerfile Source:
https://github.com/RiverSafeUK/eze-cli


_Updated: 26/07/2021_
```
# Total Uncompressed: 794.62MB
#
# Base Sizes
# ====================================
# Base Linux Image           114.4 MB
# Git Support                 78.2 MB
# Eze                         2.17 MB
#
# Language Sizes
# ====================================
# Maven + Java jdk 11        221.3 MB
# Node + npm                 139.0 MB
#
# Tool Sizes
# ====================================
# semgrep                    209.0 MB
# aqua/trivy                  35.4 MB
# cyclonedx-cli               32.4 MB
# anchore/grype               19.9 MB
# anchore/syft                15.1 MB
# gitleaks                    11.8 MB
# truffleHog3                 6.45 MB
# node/@cyclonedx/bom         4.51 MB
# python/cyclonedx-bom        4.39 MB
# python/bandit               1.37 MB
# python/piprot               1.35 MB
# python/safety               0.86 MB
#
# ====================================
# Total Image Size           897.6 MB
#
```

