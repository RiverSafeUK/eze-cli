# syntax=docker/dockerfile:1
#
# ===============================
# EZE DEVELOPMENT DOCKER IMAGE
# preloaded with Open Source Tools
# ===============================
# https://docs.docker.com/engine/reference/builder/
# Ps: Slim down and Tailor for CI deployment, or to add Premium Tools
#
# Base Sizes
# ====================================
# Base Linux Image           114.5 MB
# Git Support                 78.2 MB
# Eze                          3.2 MB
#
# Language Sizes
# ====================================
# Maven + Java jdk 11        240.1 MB
# Node + npm                 187.0 MB
# Python + pip               200.0 MB
#
# Tool Sizes
# ====================================
# semgrep                    109.0 MB
# checkmarx/kics              80.3 MB
# aqua/trivy                  35.4 MB
# cyclonedx-cli               32.4 MB
# anchore/grype               22.3 MB
# anchore/syft                16.9 MB
# gitleaks                    11.8 MB
# truffleHog3                  5.6 MB
# python/cyclonedx-bom         4.9 MB
# node/@cyclonedx/bom          4.7 MB
# python/bandit                1.4 MB
# python/safety                0.2 MB
# python/piprot                0.1 MB
#

# AB#1044 : Extract Debian binaries from kics offical docker image
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

# Explicitly fail docker build if commands below fail
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# set Work Dir
WORKDIR /data

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
    PATH="$PATH:/home/ezeuser/.dotnet/tools" \
    # kics env, add kics into PATH
    PATH="$PATH:/app/bin"

# apt-get installs
RUN apt-get update \
    && mkdir -p /usr/share/man/man1 /usr/share/man/man2 \
    # Install maven (java tool dependency)
    # WORKAROUND: Fix to be able to install openjdk-11-jre. https://stackoverflow.com/a/61816355
    && mkdir -p /usr/share/man/man1 /usr/share/man/man2 \
    && apt-get install -y --no-install-recommends openjdk-11-jre-headless \
    && apt-get install -y --no-install-recommends maven \
    # Install node (npm tool dependency)
    && curl -fsSL https://deb.nodesource.com/setup_current.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    # Install python (eze + pip tool dependency)
    && apt-get install -y --no-install-recommends python3 python3-pip \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/debconf/templates.dat* \
    && rm -rf /var/cache/debconf/*-old \
    && rm -rf /var/lib/dpkg/status* \
    && rm -rf /var/log/*

# install node security tools
RUN npm install -g @cyclonedx/bom --only=production \
    && npm cache clean --force \
    && npm prune --production

# install pip tools
RUN pip3 install --no-cache-dir semgrep truffleHog3 bandit piprot safety cyclonedx-bom \
    # BUGFIX: AB-887: WORKAROUND: cyclonedx-bom exe used by python/cyclonedx-bom and node/cyclonedx-bom
    # deleting python/cyclonedx-bom as we use it's cyclonedx-py exe
    && rm `which cyclonedx-bom`


# Install Anchore tools (grype / syft)
RUN set -o pipefail \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install CycloneDX BOM tools
RUN curl -sSfL https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.22.0/cyclonedx-linux-x64 -o cyclonedx-cli \
    && mv cyclonedx-cli /usr/local/bin/cyclonedx-cli \
    && chmod +x /usr/local/bin/cyclonedx-cli

# Install Trivy Docker tools
RUN curl -sSfL https://github.com/aquasecurity/trivy/releases/download/v0.18.2/trivy_0.18.2_Linux-64bit.deb -o trivy_0.18.2_Linux-64bit.deb \
    && dpkg -i trivy_0.18.2_Linux-64bit.deb \
    && rm trivy_0.18.2_Linux-64bit.deb

# Install Gitleaks scanner tool
RUN curl -sSfL https://github.com/zricethezav/gitleaks/releases/download/v7.5.0/gitleaks-linux-amd64 -o gitleaks \
    && mv gitleaks /usr/local/bin/gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && gitleaks --version

# Add kics binaries from offical image
COPY --from=kics_docker_image /app/bin/kics /app/bin/kics
COPY --from=kics_docker_image /app/bin/assets/queries /app/bin/assets/queries
COPY --from=kics_docker_image /app/bin/assets/libraries/* /app/bin/assets/libraries/

# install dotnet/C# tools
RUN dotnet tool install --global CycloneDX

#
## install eze
COPY scripts/eze-cli-*.tar.gz /tmp/eze-cli-latest.tar.gz
RUN pip3 install --no-cache-dir /tmp/eze-cli-latest.tar.gz \
    && rm /tmp/eze-cli-latest.tar.gz

# create app user
RUN useradd --create-home ezeuser
USER ezeuser

# cli eze
# run with "docker run --rm -v $(pwd -W):/data eze-docker --version"
# mount folder to scan to "/data"
ENTRYPOINT ["eze"]