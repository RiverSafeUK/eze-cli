"""helper functions for dealing with language helpers"""

from eze.utils.language.java import get_maven_projects
from eze.utils.language.dotnet import get_dotnet_projects, get_dotnet_solutions
from eze.utils.language.node import get_npm_projects
from eze.utils.language.python import get_requirements_projects, get_poetry_projects, get_piplock_projects
from eze.utils.language.iac import get_dockerfile_projects, get_terraform_projects


def get_projects() -> dict:
    """give a list of projects"""
    return {
        "MAVEN": get_maven_projects(),
        "DOTNET_PROJECT": get_dotnet_projects(),
        "DOTNET_SOLUTION": get_dotnet_solutions(),
        "NODE": get_npm_projects(),
        "PYTHON_REQUIREMENTS": get_requirements_projects(),
        "PYTHON_POETRY": get_poetry_projects(),
        "PYTHON_PIPLOCK": get_piplock_projects(),
        "IAC_DOCKER": get_dockerfile_projects(),
        "IAC_TERRAFORM": get_terraform_projects(),
    }
