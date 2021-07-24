#!/usr/bin/env python

import re
from os import path
from pathlib import Path

from setuptools import find_packages, setup


def read_requirements(file_name: str) -> list:
    """Reads a given requirements file name and returns str array"""
    file_directory = path.abspath(path.dirname(__file__))
    with open(path.join(file_directory, file_name), encoding="utf-8") as file:
        requirements = [s for s in [line.split("#", 1)[0].strip(" \t\n") for line in file] if s != ""]
    return requirements


def read_version() -> str:
    """Reads version from eze/__init__.py"""
    data_folder = Path(path.dirname(__file__))
    file_path = data_folder / "eze" / "__init__.py"
    with open(file_path, encoding="utf-8") as file:
        content = file.read()
    return re.search(r"__version__ = \"([^']+)\"", content).group(1)


setup(
    version=read_version(),
    packages=find_packages(exclude=["tests.*", "tests"]),
    install_requires=read_requirements("requirements.txt"),
)
