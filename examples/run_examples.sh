#!/usr/bin/env bash
#
#############################################
# run examples
#############################################
#

echo "========================================="
echo "BUILDING EZE CLI"
echo "========================================="

cd ..
make cli > /dev/null
cd examples

echo -e "\e[0m"
echo "========================================="
echo "RUNNING EZE via CLI"
echo "========================================="
echo ""

echo "-----------------------------------------"
echo "EZE secrets example"
echo "-----------------------------------------"
cd capability/secrets/

eze test
cd ../..

echo "-----------------------------------------"
echo "EZE container example"
echo "-----------------------------------------"
cd language/container/
eze test
cd ../..

echo "-----------------------------------------"
echo "EZE node example"
echo "-----------------------------------------"
cd language/node/
eze test
cd ../..

echo "-----------------------------------------"
echo "EZE python example"
echo "-----------------------------------------"
cd language/python/
eze test
cd ../..

echo "-----------------------------------------"
echo "EZE java example"
echo "-----------------------------------------"
cd language/java/
eze test
cd ../..