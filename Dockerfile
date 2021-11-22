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
# ====================================
# Total Image Size           948.0 MB
#
#

# base image
FROM python:3.8-slim-buster

#
# Explicitly fail docker build if commands below fail
SHELL ["/bin/bash", "-o", "pipefail", "-c"]


#
# Install apt-get Java Dependencies
RUN apt-get update \
    # WORKAROUND: Fix to be able to install openjdk-11-jre. https://stackoverflow.com/a/61816355
    && mkdir -p /usr/share/man/man1 /usr/share/man/man2 \
    && apt-get install -y --no-install-recommends openjdk-11-jre-headless \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && echo "SIZETAG:Language:Maven + Java jdk 11"

#
# Install apt-get Other Dependencies
RUN apt-get update \
    && mkdir -p /usr/share/man/man1 /usr/share/man/man2 \
    && apt-get install -y --no-install-recommends git curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && echo "SIZETAG:Base:Git Support"

#
# Install maven (java tool dependency)
ENV MAVEN_HOME=/usr/share/maven \
    MAVEN_CONFIG=/data/.m2 \
    JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
RUN apt-get update \
    && apt-get install -y --no-install-recommends maven \
    && chmod +x /usr/bin/mvn \
    && echo "SIZETAG:Language:Maven + Java jdk 11"

#
# Install node (tool dependency)
ENV NODE_ENV production
RUN set -o pipefail \
    && curl -fsSL https://deb.nodesource.com/setup_current.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && echo "SIZETAG:Language:Node + npm"

#
## install node security tools
RUN npm install -g @cyclonedx/bom --only=production \
    && echo "SIZETAG:Tool:node/@cyclonedx/bom"

#
# Install Tools
## install pip based tools
RUN pip3 install --no-cache-dir semgrep && echo "SIZETAG:Tool:semgrep"
RUN pip3 install --no-cache-dir truffleHog3 && echo "SIZETAG:Tool:truffleHog3"
RUN pip3 install --no-cache-dir bandit && echo "SIZETAG:Tool:python/bandit"
RUN pip3 install --no-cache-dir piprot && echo "SIZETAG:Tool:python/piprot"
RUN pip3 install --no-cache-dir safety && echo "SIZETAG:Tool:python/safety"
RUN pip3 install --no-cache-dir cyclonedx-bom && echo "SIZETAG:Tool:python/cyclonedx-bom"

# BUGFIX: AB-887: WORKAROUND: cyclonedx-bom exe used by python/cyclonedx-bom and node/cyclonedx-bom
# deleting python/cyclonedx-bom as we use it's cyclonedx-py exe
RUN rm `which cyclonedx-bom`

#
## Install Anchore tools
RUN set -o pipefail \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
    && echo "SIZETAG:Tool:anchore/grype"
RUN set -o pipefail \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
    && echo "SIZETAG:Tool:anchore/syft"

#
## Install CycloneDX BOM tools
RUN curl -sSfL https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.15.2/cyclonedx-linux-x64 -o cyclonedx-cli \
    && mv cyclonedx-cli /usr/local/bin/cyclonedx-cli \
    && chmod +x /usr/local/bin/cyclonedx-cli \
    && echo "SIZETAG:Tool:cyclonedx-cli"
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

#
## Install Trivy Docker tools
RUN curl -sSfL https://github.com/aquasecurity/trivy/releases/download/v0.18.2/trivy_0.18.2_Linux-64bit.deb -o trivy_0.18.2_Linux-64bit.deb \
    && dpkg -i trivy_0.18.2_Linux-64bit.deb \
    && rm trivy_0.18.2_Linux-64bit.deb \
    && echo "SIZETAG:Tool:aqua/trivy"

#
## Install Gitleaks scanner tool
RUN curl -sSfL https://github.com/zricethezav/gitleaks/releases/download/v7.5.0/gitleaks-linux-amd64 -o gitleaks \
    && mv gitleaks /usr/local/bin/gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && gitleaks --version \
    && echo "SIZETAG:Tool:gitleaks"

#
## Install Kics tools
RUN set -o pipefail \
    && curl -sSfL https://raw.githubusercontent.com/Checkmarx/kics/master/install.sh | sh -s -- -b /usr/local/bin \
    && echo "SIZETAG:Tool:checkmarx/kics"

#
## install eze
COPY scripts/eze-cli-*.tar.gz /tmp/eze-cli-latest.tar.gz
RUN pip3 install --no-cache-dir /tmp/eze-cli-latest.tar.gz \
    && rm /tmp/eze-cli-latest.tar.gz \
    && echo "SIZETAG:Base:Eze"

#
# set Work Dir
WORKDIR /data

#
# Remove Docker Build Tools and cleanup logs
RUN apt-get --purge autoremove -y curl \
    && apt-get clean \
    && npm cache clean --force \
    && npm prune --production \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/debconf/templates.dat* \
    && rm -rf /var/cache/debconf/*-old \
    && rm -rf /var/lib/dpkg/status* \
    && rm -rf /var/log/*

#
# create app user
RUN useradd --create-home ezeuser
USER ezeuser

# cli eze
# run with "docker run --rm -v $(pwd -W):/data eze-docker --version"
# mount folder to scan to "/data"
ENTRYPOINT ["eze"]