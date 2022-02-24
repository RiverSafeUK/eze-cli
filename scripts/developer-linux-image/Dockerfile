# syntax=docker/dockerfile:1
#
# ===============================
# EZE DEVELOPMENT DOCKER IMAGE
# preloaded with Open Source Tools
# ===============================
# https://docs.docker.com/engine/reference/builder/
# Larger developer linux box for testing commands from windows
#

# Extract Debian binaries from kics offical docker image
# no binaries provided via github, unsafe to run docker in docker
# see https://github.com/Checkmarx/kics/blob/master/Dockerfile.debian
# see https://github.com/Checkmarx/kics/releases (v1.5.2)
FROM checkmarx/kics:v1.5.2-debian as kics_docker_image

# base image
# comes with dotnet/git/curl/wget packages installed
# https://github.com/dotnet/dotnet-docker//blob/main/src/sdk/6.0/bullseye-slim/amd64/Dockerfile
# https://github.com/dotnet/dotnet-docker//blob/main/src/aspnet/6.0/bullseye-slim/amd64/Dockerfile
# https://github.com/dotnet/dotnet-docker//blob/main/src/runtime/6.0/bullseye-slim/amd64/Dockerfile
FROM mcr.microsoft.com/dotnet/sdk:6.0-bullseye-slim

#
# Explicitly fail docker build if commands below fail
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Setup Environment Variables
ENV \
    # java env
    MAVEN_HOME=/usr/share/maven \
    MAVEN_CONFIG=/data/.m2 \
    JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 \
    # node env
    NODE_ENV=production \
    # python env
    # http://bugs.python.org/issue19846
    # > At the moment, setting "LANG=C" on a Linux system *fundamentally breaks Python 3*, and that's not OK.
    LANG=C.UTF-8 \
    # CycloneDX BOM tools env
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 \
    # dotnet env, add tools into PATH
    PATH="$PATH:$HOME/.dotnet/tools/" \
    # kics env, add kics into PATH
    PATH="$PATH:/app/bin"

RUN set -o pipefail \
    # Update apt-get packages
    && apt-get update \
    && apt-get clean \
    # Install apt-get IDE & Make Dependencies
    && apt-get install -y --no-install-recommends make nano \
    # Install maven (java tool dependency)
    # WORKAROUND: Fix to be able to install openjdk-11-jre. https://stackoverflow.com/a/61816355
    && mkdir -p /usr/share/man/man1 /usr/share/man/man2 \
    && apt-get install -y --no-install-recommends openjdk-11-jre-headless \
    && apt-get install -y --no-install-recommends maven \
    && chmod +x /usr/bin/mvn \
    # Install node (npm tool dependency)
    && curl -fsSL https://deb.nodesource.com/setup_current.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    # Install python
    && apt-get install -y --no-install-recommends python3 python3-pip \

    # CLEAN
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

#
# install npm tools
RUN npm install -g @cyclonedx/bom --only=production

#
# install pip tools
RUN pip3 install --no-cache-dir semgrep truffleHog3 bandit piprot safety cyclonedx-bom \
    # BUGFIX: AB-887: WORKAROUND: cyclonedx-bom exe used by python/cyclonedx-bom and node/cyclonedx-bom
    # deleting python/cyclonedx-bom as we use it's cyclonedx-py exe
    && rm `which cyclonedx-bom`

#
# install dotnet/C# tools
RUN dotnet tool install --global CycloneDX

#
# install linux script tools
RUN set -o pipefail \
    ## Install Anchore tools
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
    ## Install CycloneDX BOM tools
    && curl -sSfL https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.15.2/cyclonedx-linux-x64 -o cyclonedx-cli \
    && mv cyclonedx-cli /usr/local/bin/cyclonedx-cli \
    && chmod +x /usr/local/bin/cyclonedx-cli \
    ## Install Trivy Docker tools
    && curl -sSfL https://github.com/aquasecurity/trivy/releases/download/v0.18.2/trivy_0.18.2_Linux-64bit.deb -o trivy_0.18.2_Linux-64bit.deb \
    && dpkg -i trivy_0.18.2_Linux-64bit.deb \
    && rm trivy_0.18.2_Linux-64bit.deb \
    ## Install Gitleaks scanner tool
    && curl -sSfL https://github.com/zricethezav/gitleaks/releases/download/v7.5.0/gitleaks-linux-amd64 -o gitleaks \
    && mv gitleaks /usr/local/bin/gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && gitleaks --version

# Add kics binaries from offical image
COPY --from=kics_docker_image /app/bin/kics /app/bin/kics
COPY --from=kics_docker_image /app/bin/assets/queries /app/bin/assets/queries
COPY --from=kics_docker_image /app/bin/assets/libraries/* /app/bin/assets/libraries/

#
# set Work Dir
WORKDIR /data

#
# create app user
RUN useradd --create-home ezeuser
USER ezeuser

# cli eze
# run with "docker run --rm -v $(pwd -W):/data eze-docker --version"
# mount folder to scan to "/data"
ENTRYPOINT ["bash"]