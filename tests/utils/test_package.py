# pylint: disable=missing-module-docstring,missing-class-docstring

import pkg_resources

from eze.plugins import base_plugins
from eze.utils.package import get_plugins


class MockPlugin:
    def get_reporters(self):
        return {}

    def get_tools(self):
        return {}


class MockEntryPoint(pkg_resources.EntryPoint):
    def load(self, *args, **kwargs):
        return MockPlugin


def test_get_plugins__empty(monkeypatch):
    def mock_iter_entry_points(group, name=None):
        return iter([])

    monkeypatch.setattr(pkg_resources, "iter_entry_points", mock_iter_entry_points)
    expected_output = {"inbuilt": base_plugins}
    output = get_plugins()
    assert output == expected_output


def test_get_plugins__with_entry(monkeypatch):
    def mock_iter_entry_points(group, name=None):
        return iter([MockEntryPoint("dummy", "src.dummy")])

    monkeypatch.setattr(pkg_resources, "iter_entry_points", mock_iter_entry_points)
    expected_output = {"inbuilt": base_plugins, "dummy": MockPlugin}
    output = get_plugins()
    assert output == expected_output
