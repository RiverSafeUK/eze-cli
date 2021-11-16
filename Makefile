##############################################
# Make File Spec
# https://www.gnu.org/software/make/
# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html
##############################################


# AUTO DETECT CORRECT LOCAL PYTHON / PIP
ifeq ($(shell which python3 2> /dev/null),)
	PYTHON = 'python'
else
	PYTHON = 'python3'
endif
ifeq ($(shell which pip3 2> /dev/null),)
	PIP = pip
else
	PIP = pip3
endif


.PHONY: install lint test

##############################################
# DEVELOPER COMMANDS
##############################################

install:
	$(PIP) install -r requirements-dev.txt  -r requirements.txt && pre-commit install

lint:
	black eze tests
	pylint --fail-under=8 --rcfile .pylintrc eze

test:
	$(PYTHON) -m pytest tests -vv --cov=eze --cov-branch --cov-report=term-missing --cov-report html:reports/coverage/cov_html --cov-report=xml:reports/coverage/coverage.xml --junitxml=reports/xunit/test-results.xml -o junit_family=xunit1 || true

test-snapshot-update:
	$(PYTHON) -m pytest tests --snapshot-update

##############################################
# EZE CLI PACKAGE COMMANDS
##############################################

# build eze package
cli-build:
	rm -f dist/*.tar.gz
	$(PYTHON) setup.py sdist
	rm -f scripts/*.tar.gz
	cp dist/*.tar.gz scripts/

# install local eze package
cli-install:
	$(PIP) install dist/eze-cli-*.tar.gz

# build and install eze package
cli: cli-build cli-install

# build and install eze package and docker image
docker: cli-build cli-install
	docker build --tag eze-cli .

# release to test pip
release-pypi-test: cli-build
	twine upload --repository testpypi dist/*

# release to test pip
release-pypi: cli-build
	twine upload dist/*

# release docker image
release-docker: cli
	docker build . -t riversafe/eze-cli:`$(PYTHON) eze/version.py` -t riversafe/eze-cli:latest
	docker push riversafe/eze-cli:`$(PYTHON) eze/version.py`
	docker push riversafe/eze-cli:latest

##############################################
# BUILD SYSTEM COMMANDS
##############################################

# Run git pre-commit hook, always run after committing code
verify:
	pre-commit run --all-file

##############################################
# MISC COMMANDS
##############################################

# for dependency analysis
dump-local-pip-versions:
	$(PIP) freeze > reports/pip-current-requirements.txt

# Run to fix black if it breaks its self locally
# tip from https://stackoverflow.com/questions/59343656/problem-with-using-black-code-formatter-cant-import-ast3
repair-black:
	$(PIP) install --force-reinstall --upgrade typed-ast black

# Run to fix pip packages
# common if you accidentally have two pythons installed and the two pip repos get muddled
# with the local pip registry being incorrect
repair-pip:
	$(PYTHON) -m pip install ––upgrade --force-reinstall pip
	$(PIP) install --upgrade --force-reinstall -r requirements-dev.txt  -r requirements.txt

# Run to fix pyenv not linking to recently installed pip packages
repair-pyenv:
	pyenv rehash

all: install verify

.DEFAULT_GOAL := all
