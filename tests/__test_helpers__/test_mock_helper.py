# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,invalid-name

from tests.__test_helpers__.mock_helper import DummyFailureTool, DummySuccessTool, DummyReporter
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestDummyFailureTool(ToolMetaTestBase):
    ToolMetaClass = DummyFailureTool
    SNAPSHOT_PREFIX = "dummy-failure-tool"


class TestDummySuccessTool(ToolMetaTestBase):
    ToolMetaClass = DummySuccessTool
    SNAPSHOT_PREFIX = "dummy-success-tool"


class TestDummyReporter(ReporterMetaTestBase):
    ReporterMetaClass = DummyReporter
    SNAPSHOT_PREFIX = "dummy-reporter"
