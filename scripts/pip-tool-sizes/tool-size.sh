#!/usr/bin/env bash

# set to debug
# set -x

rm -rf ~/.virtualenvs/tool-size-tester
python -m venv ~/.virtualenvs/tool-size-tester
source ~/.virtualenvs/tool-size-tester/Scripts/activate
pip install -q $1
python tool-size.py
deactivate