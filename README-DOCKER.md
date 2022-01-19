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


# Tailoring Image
It's recommended for organisations with mature devops teams to download and tailor this Docker image, adding/removing the pre-installed security tools as needed to optimise size of the image, as well as making their own _.ezerc.toml_ files.

_*Aka: Some tools for example semgrep are upto 200mb by themselves, tailoring the image to remove unused tools will save significant amounts of space_

Dockerfile Source:
https://github.com/RiverSafeUK/eze-cli/Dockerfile
