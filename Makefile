##############################################
# Make File Spec
# https://www.gnu.org/software/make/
# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html
##############################################

.PHONY: install lint test

##############################################
# DEVELOPER COMMANDS
##############################################

install:
	python -m pip install -r requirements-dev.txt  -r requirements.txt && pre-commit install

lint:
	black eze tests
	pylint --fail-under=8 --rcfile .pylintrc eze

test:
	python -m pytest tests -vv --cov=eze --cov-branch --cov-report=term-missing --cov-report html:reports/coverage/cov_html --cov-report=xml:reports/coverage/coverage.xml --junitxml=reports/xunit/test-results.xml -o junit_family=xunit1 || true

test-snapshot-update:
	python -m pytest tests --snapshot-update

##############################################
# EZE CLI PACKAGE COMMANDS
##############################################

# build eze package
cli-build:
	rm -f dist/*.tar.gz
	python setup.py sdist
	rm -f scripts/*.tar.gz
	cp dist/*.tar.gz scripts/

# install local eze package
cli-install:
	pip install dist/eze-cli-*.tar.gz

# build and install eze package
cli: cli-build cli-install

# build and install eze package and docker image
docker: cli-build cli-install
	docker build --tag eze-cli .

# release to test pip
release-pypi-test: plugin-build
	twine upload --repository testpypi dist/*

# release to test pip
release-pypi: plugin-build
	twine upload dist/*

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
	pip freeze > reports/pip-current-requirements.txt

# Run to fix black if it breaks its self locally
# tip from https://stackoverflow.com/questions/59343656/problem-with-using-black-code-formatter-cant-import-ast3
repair-black:
	pip install --force-reinstall --upgrade typed-ast black

# Run to fix pip packages
# common if you accidentally have two pythons installed and the two pip repos get muddled
# with the local pip registry being incorrect
repair-pip:
	python -m pip install ––upgrade --force-reinstall pip
	pip install --upgrade --force-reinstall -r requirements-dev.txt  -r requirements.txt

# Run to fix pyenv not linking to recently installed pip packages
repair-pyenv:
	pyenv rehash

all: install verify

.DEFAULT_GOAL := all
