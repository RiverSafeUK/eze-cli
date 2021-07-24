"""Git helpers
"""
import os
from pathlib import Path

from pydash import py_

MAX_RECURSION: int = 10

try:
    import git
except ImportError:
    # WORKAROUND: see "ImportError: Bad git executable."
    # see https://github.com/gitpython-developers/GitPython/issues/816
    print("Error: Git not installed, eze will not be able to detect git branches")


def get_active_branch(git_dir: str) -> object:
    """recursive git repo check will return branch object if found"""
    git_path = Path(git_dir)
    i = 0
    while git_path and i < MAX_RECURSION:
        branch = _get_active_branch(git_path)
        if branch:
            return branch
        git_path /= ".."
        i += 1

    return None


def _get_active_branch(git_dir: str) -> object:
    """non-recursive git repo check will return branch object if found"""
    try:
        repo = git.Repo(git_dir)
        git_branch = repo.active_branch
    except NameError:
        # INFO: git will not exist when git not installed
        git_branch = None
    except git.GitError:
        # in particular git.InvalidGitRepositoryError
        git_branch = None
    except TypeError:
        # INFO: CI often checkout as detached head which doesn't technically have a branch
        # aka throws "TypeError: HEAD is a detached symbolic reference as it points to xxxx"
        git_branch = None
    except OSError:
        git_branch = None

    return git_branch


def get_active_branch_uri(git_dir: str) -> str:
    """given dir will check repo latest uri"""
    branch = get_active_branch(git_dir)
    git_branchname = py_.get(branch, "repo.remotes.origin.url", None)
    if git_branchname:
        return git_branchname

    # GET BRANCHNAME FROM Microsoft ADO
    # Build.Repository.Uri = BUILD_REPOSITORY_URI
    # https://docs.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml
    ado_uri = os.environ.get("BUILD_REPOSITORY_URI")
    if ado_uri:
        return ado_uri

    # GET BRANCHNAME FROM AWS Amplify
    # AWS_CLONE_URL
    # https://docs.aws.amazon.com/amplify/latest/userguide/environment-variables.html#amplify-console-environment-variables
    aws_uri = os.environ.get("AWS_CLONE_URL")
    if aws_uri:
        return aws_uri

    return None


def get_active_branch_name(git_dir: str) -> str:
    """given dir will check repo latest branch"""
    branch = get_active_branch(git_dir)
    git_branchname = py_.get(branch, "name", None)
    if git_branchname:
        return git_branchname

    # GET BRANCHNAME FROM Microsoft ADO
    # Build.SourceBranchName = BUILD_SOURCEBRANCHNAME
    # https://docs.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml
    ado_branchname = os.environ.get("BUILD_SOURCEBRANCHNAME")
    if ado_branchname:
        return ado_branchname

    # GET BRANCHNAME FROM AWS Amplify
    # AWS_BRANCH
    # https://docs.aws.amazon.com/amplify/latest/userguide/environment-variables.html#amplify-console-environment-variables
    aws_branchname = os.environ.get("AWS_BRANCH")
    if aws_branchname:
        return aws_branchname

    return None
