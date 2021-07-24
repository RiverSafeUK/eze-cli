# pylint: disable=missing-module-docstring,missing-class-docstring
import os
from unittest import mock
from unittest.mock import patch

from git import InvalidGitRepositoryError

from eze.utils import git


class MockGitBranch:
    def __init__(self):
        self.name = "feature/helloworld"
        self.repo = {"remotes": {"origin": {"url": "https://some-repo.some-domain.com"}}}


class MockSuccessGitRepo:
    def __init__(self):
        self.active_branch = MockGitBranch()


class MockUnsuccessGitRepo:
    def __getattribute__(self, key):
        if key == "active_branch":
            raise InvalidGitRepositoryError("No git repo error")


class MockUnsuccessDetachedGitRepo:
    def __getattribute__(self, key):
        if key == "active_branch":
            raise TypeError("HEAD is a detached symbolic reference as it points to xxxx")


class MockSimulateGitNotInstalledGitRepo:
    def __getattribute__(self, key):
        if key == "active_branch":
            raise NameError("When git not installed setup_mock, then will make git undefined")


@mock.patch.dict(os.environ, {"BUILD_SOURCEBRANCHNAME": "", "AWS_BRANCH": ""})
@patch("git.Repo")
def test_get_active_branch_name__success(mock_repo):
    mock_repo.return_value = MockSuccessGitRepo()

    expected_output = "feature/helloworld"
    output = git.get_active_branch_name("dir/foobar/")
    assert output == expected_output


@mock.patch.dict(os.environ, {"BUILD_SOURCEBRANCHNAME": "", "AWS_BRANCH": ""})
@patch("git.Repo")
def test_get_active_branch_name__unsuccess(mock_repo):
    mock_repo.return_value = MockUnsuccessGitRepo()

    expected_output = None
    output = git.get_active_branch_name("dir/foobar/")
    assert output == expected_output


@mock.patch.dict(os.environ, {"BUILD_SOURCEBRANCHNAME": "main_thing", "AWS_BRANCH": ""})
@patch("git.Repo")
def test_get_active_branch_name__success_with_ado_ci(mock_repo):
    mock_repo.return_value = MockUnsuccessDetachedGitRepo()

    expected_output = "main_thing"
    output = git.get_active_branch_name("dir/foobar/")
    assert output == expected_output


@mock.patch.dict(os.environ, {"BUILD_SOURCEBRANCHNAME": "main_thing", "AWS_BRANCH": ""})
@patch("git.Repo")
def test_get_active_branch_name__success_with_ado_ci_and_no_git_repo(mock_repo):
    mock_repo.return_value = MockUnsuccessGitRepo()

    expected_output = "main_thing"
    output = git.get_active_branch_name("dir/foobar/")
    assert output == expected_output


@mock.patch.dict(os.environ, {"BUILD_SOURCEBRANCHNAME": "", "AWS_BRANCH": "main_aws_thing"})
@patch("git.Repo")
def test_get_active_branch_name__success_with_aws_amplify_ci(mock_repo):
    mock_repo.return_value = MockUnsuccessDetachedGitRepo()

    expected_output = "main_aws_thing"
    output = git.get_active_branch_name("dir/foobar/")
    assert output == expected_output


@patch("git.Repo")
@mock.patch.dict(os.environ, {"BUILD_SOURCEBRANCHNAME": "", "AWS_BRANCH": "main_aws_thing"})
def test_get_active_branch_name__success_with_no_git_installed(mock_repo):
    mock_repo.return_value = MockSimulateGitNotInstalledGitRepo()
    expected_output = "main_aws_thing"
    output = git.get_active_branch_name("dir/foobar/")
    assert output == expected_output


@mock.patch.dict(os.environ, {"BUILD_REPOSITORY_URI": "", "AWS_CLONE_URL": ""})
@patch("git.Repo")
def test_get_active_branch_uri__success(mock_repo):
    mock_repo.return_value = MockSuccessGitRepo()

    expected_output = "https://some-repo.some-domain.com"
    output = git.get_active_branch_uri("dir/foobar/")
    assert output == expected_output


@mock.patch.dict(os.environ, {"BUILD_REPOSITORY_URI": "", "AWS_CLONE_URL": ""})
@patch("git.Repo")
def test_get_active_branch_uri__unsuccess(mock_repo):
    mock_repo.return_value = MockUnsuccessGitRepo()

    expected_output = None
    output = git.get_active_branch_uri("dir/foobar/")
    assert output == expected_output


@mock.patch.dict(os.environ, {"BUILD_REPOSITORY_URI": "https://ado-repo.com", "AWS_CLONE_URL": ""})
@patch("git.Repo")
def test_get_active_branch_uri__success_with_ado_ci(mock_repo):
    mock_repo.return_value = MockUnsuccessDetachedGitRepo()

    expected_output = "https://ado-repo.com"
    output = git.get_active_branch_uri("dir/foobar/")
    assert output == expected_output


@mock.patch.dict(os.environ, {"BUILD_REPOSITORY_URI": "https://ado-repo.com", "AWS_CLONE_URL": ""})
@patch("git.Repo")
def test_get_active_branch_uri__success_with_ado_ci_and_no_git_repo(mock_repo):
    mock_repo.return_value = MockUnsuccessGitRepo()

    expected_output = "https://ado-repo.com"
    output = git.get_active_branch_uri("dir/foobar/")
    assert output == expected_output


@mock.patch.dict(os.environ, {"BUILD_REPOSITORY_URI": "", "AWS_CLONE_URL": "https://aws-repo.com"})
@patch("git.Repo")
def test_get_active_branch_uri__success_with_aws_amplify_ci(mock_repo):
    mock_repo.return_value = MockUnsuccessDetachedGitRepo()

    expected_output = "https://aws-repo.com"
    output = git.get_active_branch_uri("dir/foobar/")
    assert output == expected_output


@patch("git.Repo")
@mock.patch.dict(os.environ, {"BUILD_REPOSITORY_URI": "", "AWS_CLONE_URL": "https://aws-repo.com"})
def test_get_active_branch_uri__success_with_no_git_installed(mock_repo):
    mock_repo.return_value = MockSimulateGitNotInstalledGitRepo()
    expected_output = "https://aws-repo.com"
    output = git.get_active_branch_uri("dir/foobar/")
    assert output == expected_output
