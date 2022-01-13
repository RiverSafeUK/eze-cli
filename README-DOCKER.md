Eze the one stop solution for security testing in modern development

The default eze-cli Dockerfile contains the eze cli, and a selection of common opensource tools out the box.

# How to Run Eze in Docker

Simple usage, mount your codebase into volume **/data**, then run docker with "test" argument

```bash
docker run -t -v FOLDER_TO_SCAN:/data riversafe/eze-cli test
```

| CLI                 | Command |
| -----------         | ----------- |
| linux/mac os bash   | ```docker run -t -v "$(pwd)":/data riversafe/eze-cli test```|
| windows git bash    | ```docker run -t -v $(pwd -W):/data riversafe/eze-cli test```|
| windows powershell  | ```docker run -t -v ${PWD}:/data riversafe/eze-cli test```|
| windows cmd         | ```docker run -t -v %cd%:/data riversafe/eze-cli test```|

# Configuring Eze
Eze runs off a local **.ezerc.toml** file, for customising your scans please edit this

When this config is not present, a sample config will be build automatically by scanning the codebase.

More information available on [github](https://github.com/RiverSafeUK/eze-cli)

# Tools Installed
List of tools, licenses, and sizes pre-installed in latest Eze Cli Dockerimage can be found using the command

```bash
docker run -t --rm riversafe/eze-cli tools list --include-source-type
docker run -t --rm riversafe/eze-cli tools help <tool-name>
aka docker run -t --rm riversafe/eze-cli tools help trufflehog
```

_Updated: 13/01/2022_

```bash
 | Type   | Name                 | Version       | License    | Sources                            | Description
                                        |
*|********|**********************|***************|************|************************************|*********************************************
****************************************|*
 | MISC   | raw                  | 0.12.0-alpha  | inbuilt    | ALL                                | input for saved eze json reports
                                        |
 | SECRET | trufflehog           | 3.0.4         | GNU        | ALL                                | opensource secret scanner
                                        |
 | SAST   | semgrep              | Not Installed | LGPL       | ALL                                | opensource multi language SAST scanner
                                        |
 | SCA    | anchore-grype        | 0.27.2        | Apache 2.0 | RUBY,NODE,JAVA,PYTHON,CONTAINER    | opensource multi language SCA and container
scanner                                 |
 | SBOM   | anchore-syft         | 0.32.2        | Apache 2.0 | RUBY,NODE,JAVA,PYTHON,GO,CONTAINER | opensource multi language and container bill
 of materials (SBOM) generation utility |
 | SECRET | gitleaks             | 7.5.0         | MIT        | ALL                                | opensource static key scanner
                                        |
 | SBOM   | java-cyclonedx       | Not Installed | Apache 2.0 | JAVA                               | opensource java bill of materials (SBOM) gen
eration utility                         |
 | SCA    | java-dependencycheck | Not Installed | Apache 2.0 | JAVA                               | opensource java SCA tool class
                                        |
 | SAST   | java-spotbugs        | Not Installed | LGPL       | JAVA                               | opensource java SAST tool class
                                        |
 | SAST   | python-safety        | 1.10.3        | MIT        | PYTHON                             | opensource python SCA scanner
                                        |
 | SCA    | python-piprot        | 0.9.11        | MIT        | PYTHON                             | opensource python outdated dependency scanne
r                                       |
 | SAST   | python-bandit        | 1.7.1         | Apache 2.0 | PYTHON                             | opensource python SAST scanner
 |
 | SBOM   | python-cyclonedx     | 1.5.3         | Apache 2.0 | PYTHON                             | opensource python bill of materials (SBOM) generation utility
 |
 | SCA    | node-npmaudit        | 8.1.4         | NPM        | NODE                               | opensource node SCA scanner
 |
 | SCA    | node-npmoutdated     | 8.1.4         | NPM        | NODE                               | opensource node outdated dependency scanner
 |
 | SBOM   | node-cyclonedx       | 3.3.1         | Apache 2.0 | NODE                               | opensource node bill of materials (SBOM) generation utility
 |
 | SCA    | container-trivy      | 0.18.2        | Apache 2.0 | CONTAINER                          | opensource container scanner
 |
 | SCA    | kics                 | 1.4.8         | Apache 2.0 | CONTAINER                          | opensource infrastructure scanner
 |

```


# Tailoring Image
It's recommended for organisations with mature devops teams to download and tailor this Docker image, adding/removing the pre-installed security tools as needed to optimise size of the image, as well as making their own _.ezerc.toml_ files.

_*Aka: Some tools for example semgrep are upto 200mb by themselves, tailoring the image to remove unused tools will save significant amounts of space_

Dockerfile Source:
https://github.com/RiverSafeUK/eze-cli/Dockerfile
