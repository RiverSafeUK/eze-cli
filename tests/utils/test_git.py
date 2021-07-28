# pylint: disable=missing-module-docstring,missing-class-docstring
import os
from unittest import mock
from unittest.mock import patch

import pytest
from git import InvalidGitRepositoryError

from eze.utils import git
from eze.utils.git import clean_url


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


@mock.patch.dict(os.environ, {"BUILD_REPOSITORY_URI": "", "AWS_CLONE_URL": ""})
@patch("git.Repo")
def test_get_active_branch_uri__success_with_git(mock_repo):
    mock_repo.return_value = MockSuccessGitRepo()

    expected_output = "https://some-repo.some-domain.com"
    output = git.get_active_branch_uri("dir/foobar/")
    assert output == expected_output


@mock.patch.dict(os.environ, {"BUILD_SOURCEBRANCHNAME": "main_thing", "AWS_BRANCH": ""})
@patch("git.Repo")
def test_get_active_branch_name__success_with_ado_ci_detached_example(mock_repo):
    mock_repo.return_value = MockUnsuccessDetachedGitRepo()

    expected_output = "main_thing"
    output = git.get_active_branch_name("dir/foobar/")
    assert output == expected_output


@patch("git.Repo")
@mock.patch.dict(os.environ, {"BUILD_SOURCEBRANCHNAME": "", "AWS_BRANCH": "main_aws_thing"})
def test_get_active_branch_name__success_with_no_git_installed(mock_repo):
    mock_repo.return_value = MockSimulateGitNotInstalledGitRepo()
    expected_output = "main_aws_thing"
    output = git.get_active_branch_name("dir/foobar/")
    assert output == expected_output


branch_test_data = [
    (
        "ado",
        {"BUILD_SOURCEBRANCHNAME": "main_ado_thing", "BUILD_REPOSITORY_URI": "https://ado-repo.com"},
        "https://ado-repo.com",
        "main_ado_thing",
    ),
    (
        "AWS_CASE",
        {"AWS_BRANCH": "main_aws_thing", "AWS_CLONE_URL": "https://aws-repo.com"},
        "https://aws-repo.com",
        "main_aws_thing",
    ),
    ("No git repo or ci checkout present", {}, None, None),
    (
        "Jenkins",
        {
            "GIT_URL": "https://Jenkins-repo.com",
            "GIT_LOCAL_BRANCH": "main_Jenkins_thing",
            "GIT_BRANCH": "/o/origin/main_Jenkins_thing",
        },
        "https://Jenkins-repo.com",
        "main_Jenkins_thing",
    ),
    (
        "IBMCLOUD",
        {
            "GIT_URL": "https://IBMCLOUD-repo.com",
            "GIT_BRANCH": "main_IBMCLOUD_thing",
        },
        "https://IBMCLOUD-repo.com",
        "main_IBMCLOUD_thing",
    ),
    (
        "GCP",
        {
            "_REPO_URL": "https://GCP-repo.com",
            "BRANCH_NAME": "main_GCP_thing",
        },
        "https://GCP-repo.com",
        "main_GCP_thing",
    ),
    (
        "Gitlab_with_credentials",
        {
            "CI_REPOSITORY_URL": "https://gitlab-ci-token:[MASKED]@gitlab.com/gitlab-examples/ci-debug-trace.git",  # nosec
            "CI_DEFAULT_BRANCH": "main_Gitlab_thing",
        },
        "https://gitlab.com/gitlab-examples/ci-debug-trace.git",
        "main_Gitlab_thing",
    ),
    (
        "Github",
        {
            "GITHUB_SERVER_URL": "https://Gitlab-repo.com",
            "GITHUB_REPOSITORY": "zapper/eze.git",
            "CI_DEFAULT_BRANCH": "main_Github_thing",
        },
        "https://Gitlab-repo.com/zapper/eze.git",
        "main_Github_thing",
    ),
]

EMPTY_HASH = {
    "BUILD_SOURCEBRANCHNAME": "",
    "BUILD_REPOSITORY_URI": "",
    "AWS_BRANCH": "",
    "AWS_CLONE_URL": "",
    "GIT_URL": "",
    "GIT_LOCAL_BRANCH": "",
    "GIT_BRANCH": "",
    "_REPO_URL": "",
    "BRANCH_NAME": "",
    "CI_REPOSITORY_URL" "CI_COMMIT_BRANCH": "",
    "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "",
    "CI_EXTERNAL_PULL_REQUEST_TARGET_BRANCH_NAME": "",
    "CI_DEFAULT_BRANCH": "",
    "GITHUB_SERVER_URL": "",
    "GITHUB_REPOSITORY": "",
    "GITHUB_REF": "",
}


@patch("git.Repo")
@pytest.mark.parametrize("title,input_os_environ,expected_repo_output,expected_branch_output", branch_test_data)
def test_get_active_branch_uri(mock_repo, title, input_os_environ, expected_repo_output, expected_branch_output):
    test_os_environ = {}
    for key in EMPTY_HASH:
        test_os_environ[key] = EMPTY_HASH[key]
    for key in input_os_environ:
        test_os_environ[key] = input_os_environ[key]
    with patch.dict(os.environ, test_os_environ, clear=True):
        mock_repo.return_value = MockUnsuccessGitRepo()
        output = git.get_active_branch_uri("dir/foobar/")
        assert output == expected_repo_output


@patch("git.Repo")
@pytest.mark.parametrize("title,input_os_environ,expected_repo_output,expected_branch_output", branch_test_data)
def test_get_active_branch_name(mock_repo, title, input_os_environ, expected_repo_output, expected_branch_output):
    test_os_environ = {}
    for key in EMPTY_HASH:
        test_os_environ[key] = EMPTY_HASH[key]
    for key in input_os_environ:
        test_os_environ[key] = input_os_environ[key]
    with patch.dict(os.environ, test_os_environ, clear=True):
        mock_repo.return_value = MockUnsuccessGitRepo()
        output = git.get_active_branch_name("dir/foobar/")
        assert output == expected_branch_output


url_test_data = [
    ("Do Nothing", "https://clean.already.com/repo", "https://clean.already.com/repo"),
    (
        "Remove Credentials",
        "https://gitlab-ci-token:[MASKED]@gitlab.com/gitlab-examples/ci-debug-trace.git",
        "https://gitlab.com/gitlab-examples/ci-debug-trace.git",
    ),
]


@pytest.mark.parametrize("title,input,expected_output", url_test_data)
def test_clean_url(title, input, expected_output):
    output = clean_url(input)
    assert output == expected_output
