# syntax=docker/dockerfile:1
#
# ===============================
# EZE DEVELOPMENT DOCKER IMAGE
# preloaded with Open Source Tools
# ===============================
# https://docs.docker.com/engine/reference/builder/
# Larger developer linux box for testing commands from windows
#

# base image
FROM python:3.9-slim-bullseye

#
# Explicitly fail docker build if commands below fail
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

#
# Install apt-get Make Dependencies
## Install editor
# https://packages.ubuntu.com/
RUN apt-get update \
    && apt-get install -y --no-install-recommends make \
    && apt-get install -y --no-install-recommends nano \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# Install maven (java tool dependency)
ENV MAVEN_HOME=/usr/share/maven \
    MAVEN_CONFIG=/data/.m2 \
    JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64

# Install node (tool dependency)
ENV NODE_ENV production

RUN set -o pipefail \
    && apt-get update \
    && apt-get clean \
    # Install apt-get Other Dependencies
    && mkdir -p /usr/share/man/man1 /usr/share/man/man2 \
    && apt-get install -y --no-install-recommends git curl \
    # Install apt-get Java Dependencies
    # WORKAROUND: Fix to be able to install openjdk-11-jre. https://stackoverflow.com/a/61816355
    && mkdir -p /usr/share/man/man1 /usr/share/man/man2 \
    && apt-get install -y --no-install-recommends openjdk-11-jre-headless \
    # Install maven (java tool dependency)
    && apt-get install -y --no-install-recommends maven \
    && chmod +x /usr/bin/mvn \
    # Install node (tool dependency)
    && curl -fsSL https://deb.nodesource.com/setup_current.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    # CLEAN
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

#
## install node security tools
RUN npm install -g @cyclonedx/bom --only=production

#
# Install Tools
## install pip based tools
RUN pip3 install --no-cache-dir \
    semgrep \
    truffleHog3 \
    bandit \
    piprot \
    safety \
    cyclonedx-bom

# BUGFIX: AB-887: WORKAROUND: cyclonedx-bom exe used by python/cyclonedx-bom and node/cyclonedx-bom
# deleting python/cyclonedx-bom as we use it's cyclonedx-py exe
RUN rm `which cyclonedx-bom`

#
## Install CycloneDX BOM tools
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1


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
    && gitleaks --version \
    ## Install Kics tools
    && curl -sSfL https://raw.githubusercontent.com/Checkmarx/kics/master/install.sh | sh -s -- -b /usr/local/bin

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