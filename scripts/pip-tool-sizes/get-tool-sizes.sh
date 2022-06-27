#!/usr/bin/env bash

# set to debug
# set -x

echo ""
echo "==============================="
echo "SIZE OF BIN TOOLS"
echo "==============================="
# ls `which grype` --block-size=K -man
echo "anchore/grype == 19.41MB"

# ls `which syft` --block-size=K -man
echo "anchore/syft == 14.60MB"

# ls `which trivy` --block-size=K -man
echo "trivy == 34.05MB"


echo ""
echo "==============================="
echo "SIZE OF NPM TOOLS"
echo "==============================="

# https://packagephobia.com/result?p=%40cyclonedx%2Fbom
echo "@cyclonedx/bom == 1.42MB"

echo ""
echo "==============================="
echo "SIZE OF PIP TOOLS"
echo "==============================="

echo ""
echo "Size of truffleHog3"
echo "==============================="
./tool-size.sh truffleHog3

echo ""
echo "Size of semgrep"
echo "==============================="
./tool-size.sh semgrep

echo ""
echo "Size of bandit"
echo "==============================="
./tool-size.sh bandit

echo ""
echo "Size of piprot"
echo "==============================="
./tool-size.sh piprot

echo ""
echo "Size of cyclonedx-bom"
echo "==============================="
./tool-size.sh cyclonedx-bom

echo ""
echo "Size of Eze"
echo "==============================="
rm -rf ~/.virtualenvs/tool-size-tester
python -m venv ~/.virtualenvs/tool-size-tester
source ~/.virtualenvs/tool-size-tester/Scripts/activate
pip install -q ../../scripts/riversafe-eze-core-*.tar.gz
python tool-size.py
deactivate