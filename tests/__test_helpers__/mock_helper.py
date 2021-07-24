"""Small setup_mock helper"""
import sys
from io import StringIO

from eze.core.config import EzeConfig
from eze.core.engine import EzeCore
from eze.core.language import LanguageManager
from eze.core.reporter import ReporterManager, ReporterMeta
from eze.core.tool import ToolManager, ToolMeta, ScanResult, ToolType
from eze.plugins.languages.python import PythonRunner


class DummyFailureTool(ToolMeta):
    """Example always failure scanner"""

    TOOL_NAME: str = "dummy-failure"
    TOOL_TYPE: ToolType = ToolType.MISC
    SOURCE_SUPPORT: list = []
    SHORT_DESCRIPTION: str = "Example short description"
    INSTALL_HELP: str = "Example install help string"
    MORE_INFO: str = "Example Config help string"
    LICENSE: str = "LICENSE X"
    EZE_CONFIG: dict = {}

    def __init__(self, config: dict = {}):
        """constructor"""
        self.config = config

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        return "X.X.X"

    async def run_scan(self) -> ScanResult:
        """Method for running a synchronous scan using tool"""
        raise Exception("Something bad")


class DummySuccessTool(ToolMeta):
    """Example always success scanner"""

    TOOL_NAME: str = "dummy-success"
    TOOL_TYPE: ToolType = ToolType.MISC
    SOURCE_SUPPORT: list = []
    SHORT_DESCRIPTION: str = "Example short description"
    INSTALL_HELP: str = "Example install help string"
    MORE_INFO: str = "Example Config help string"
    LICENSE: str = "LICENSE X"
    EZE_CONFIG: dict = {}

    def __init__(self, config: dict = {}):
        """constructor"""
        self.config = config

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        return "X.X.X"

    async def run_scan(self) -> ScanResult:
        """Method for running a synchronous scan using tool"""
        return ScanResult()


class DummyReporter(ReporterMeta):
    """TBC something that consumes Scans"""

    REPORTER_NAME: str = "dummy"
    SHORT_DESCRIPTION: str = "Example short description"
    INSTALL_HELP: str = "Example install help string"
    MORE_INFO: str = "Example Config help string"
    LICENSE: str = "LICENSE X"
    EZE_CONFIG: dict = {}

    def __init__(self, config: dict = {}):
        """constructor"""
        self.config = config

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return "version string"

    async def run_report(self, scan_results: list):
        """Method for taking scan results and turning then into report output"""

        return {"title": "test report wip"}


DEFAULT_MOCK_TOOLS = {"success-tool": DummySuccessTool, "failure-tool": DummyFailureTool}

DEFAULT_MOCK_REPORTERS = {"testee-reporter": DummyReporter}

DEFAULT_MOCK_LANGUAGES = {
    "testee-language": PythonRunner,
}

DEFAULT_MOCK_CONFIG = {"success-tool": {"some": "config"}, "scan": {}}


def get_dummy_plugin(
    tools: dict = DEFAULT_MOCK_TOOLS, reporters: dict = DEFAULT_MOCK_REPORTERS, languages: dict = DEFAULT_MOCK_LANGUAGES
):
    class DummyPlugin:
        """Dummy Plugin"""

        @staticmethod
        def get_tools() -> dict:
            """Dummy get tools"""
            return tools

        @staticmethod
        def get_reporters() -> dict:
            """Dummy get reporters"""
            return reporters

        @staticmethod
        def get_languages() -> dict:
            """Dummy get languages"""
            return languages

    return DummyPlugin


def setup_mock(
    eze_config: dict = DEFAULT_MOCK_CONFIG, tools: dict = DEFAULT_MOCK_TOOLS, reporters: dict = DEFAULT_MOCK_REPORTERS
):
    """Mock the services being used in app"""
    EzeCore.reset_instance()
    EzeConfig.reset_instance()
    ToolManager.reset_instance()
    ReporterManager.reset_instance()
    LanguageManager.reset_instance()

    EzeConfig.set_instance([eze_config])

    dummy_plugin_class = get_dummy_plugin(tools, reporters)

    ToolManager.set_instance({"dummy-plugin": dummy_plugin_class})
    ReporterManager.set_instance({"dummy-plugin": dummy_plugin_class})
    LanguageManager.set_instance({"dummy-plugin": dummy_plugin_class})


def teardown_mock():
    """Unmock the services being used in app"""
    EzeCore.reset_instance()
    EzeConfig.reset_instance()
    ToolManager.reset_instance()
    ReporterManager.reset_instance()
    LanguageManager.reset_instance()


def mock_print() -> StringIO:
    """Mock the print command"""
    mocked_print_output = StringIO()
    sys.stdout = mocked_print_output
    return mocked_print_output


def unmock_print():
    """Unmock the print command"""
    sys.stdout = sys.__stdout__
