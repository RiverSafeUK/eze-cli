#!/usr/bin/env bash
#
#############################################
# run examples
#############################################
#

echo "========================================="
echo "BUILDING DOCKER"
echo "========================================="
cd ..
make docker > /dev/null
cd examples

echo -e "\e[0m"
echo "========================================="
echo "RUNNING EZE via DOCKER"
echo "========================================="
echo ""

echo "-----------------------------------------"
echo "EZE secrets example"
echo "-----------------------------------------"
cd capability/secrets/
docker run --rm -t -v $(pwd -W):/data -v $(pwd -W)/../reports:/reports eze-cli test -s linux
cd ../..

echo "-----------------------------------------"
echo "EZE container example"
echo "-----------------------------------------"
cd language/container/
docker run --rm -t -v $(pwd -W):/data -v $(pwd -W)/../reports:/reports eze-cli test -s linux
cd ../..

echo "-----------------------------------------"
echo "EZE node example"
echo "-----------------------------------------"
cd language/node/
docker run --rm -t -v $(pwd -W):/data -v $(pwd -W)/../reports:/reports eze-cli test -s linux
cd ../..

echo "-----------------------------------------"
echo "EZE python example"
echo "-----------------------------------------"
cd language/python/
docker run --rm -t -v $(pwd -W):/data -v $(pwd -W)/../reports:/reports eze-cli test -s linux
cd ../..

echo "-----------------------------------------"
echo "EZE java example"
echo "-----------------------------------------"
cd language/java/
docker run --rm -t -v $(pwd -W):/data -v $(pwd -W)/../reports:/reports eze-cli test -s linux
cd ../..
