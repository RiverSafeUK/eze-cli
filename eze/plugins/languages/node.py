# """Node Language Runner module"""
#
# from eze.core.enums import SourceType
# from eze.core.autoconfig import LanguageRunnerMeta
# from eze.plugins.tools.node_cyclonedx import NodeCyclonedxTool
# from eze.plugins.tools.node_npmaudit import NpmAuditTool
# from eze.plugins.tools.node_npmoutdated import NpmOutdatedTool
# from eze.plugins.tools.semgrep import SemGrepTool
# from eze.plugins.tools.trufflehog import TruffleHogTool
# from eze.utils.cli import extract_cmd_version
#
#
# class NodeRunner(LanguageRunnerMeta):
#     """Base class for node language runner, also has utilities"""
#
#     LANGUAGE_NAME: str = "node"
#     SOURCE_TYPE: SourceType = SourceType.NODE
#     SHORT_DESCRIPTION: str = "Node (.js, package.json)"
#     INSTALL_HELP: str = """Python Runner
# =================================
# Scan npm packages for old and vulnerable packages
# and running secret and semgrep sast on raw python files
# lastly generate SBOM using cyclonedx
#
# Tips and Tricks
# =================================
# Many node security tools will require "npm install" ran,
# and will fail if "npm install" fails
#
# "npm install" will be automatically run when a package.json is detected
# """
#     MORE_INFO: str = """https://nodejs.org/en/"""
#
#     FILE_PATTERNS: dict = {"NPM": "package.json$", "NODE_FILE": ".*\\.js$"}
#     FOLDER_PATTERNS: dict = {}
#
#     _installed_dependency: bool = False
#
#     @staticmethod
#     def check_installed() -> str:
#         """Method for detecting if tool installed and ready to run scan, returns version installed"""
#         version = extract_cmd_version(["node", "--version"])
#         npm_version = extract_cmd_version(["npm", "--version"])
#         if not version:
#             return "inbuilt (node: none)"
#         return f"inbuilt (node: {version}, npm:{npm_version})"
#
#     def pre_test(self) -> list:
#         """Method for running a pre test builds on project"""
#         # NOTE: npm installed individual via 'utils.language.node.install_node_dependencies()' by tools
#
#     def create_ezerc(self) -> dict:
#         """Method for building a dynamic ezerc.toml fragment"""
#         return {
#             "fragment": f"""
# [{self.LANGUAGE_NAME}]
# # Node codebase
# tools = ['{SemGrepTool.TOOL_NAME}', '{TruffleHogTool.TOOL_NAME}', '{NpmAuditTool.TOOL_NAME}', '{NpmOutdatedTool.TOOL_NAME}', '{NodeCyclonedxTool.TOOL_NAME}']
#     [{self.LANGUAGE_NAME}.{SemGrepTool.TOOL_NAME}]
#     REPORT_FILE = ".eze/semgrep-{self.LANGUAGE_NAME}-report.json"
#     PRINT_TIMING_INFO = false
#     EXCLUDE = [
#         "tests"
#     ]
#     [{self.LANGUAGE_NAME}.{TruffleHogTool.TOOL_NAME}]
#     REPORT_FILE = ".eze/truffleHog-{self.LANGUAGE_NAME}-report.json"
#     SOURCE = ["."]
#     NO_ENTROPY = false
#     INCLUDE_FULL_REASON = true
#     IGNORED_FILES = [
#     ]
#     EXCLUDE = [
#         ".*\\\\.(jpe?g|png|svg|eot|ttf|exe|map|lock|woff|pytest_cache)$",
#         ".*//trufflehog-report.json$",
#         ".*\\\\.DS_Store"
#     ]
#     [{self.LANGUAGE_NAME}.{NpmAuditTool.TOOL_NAME}]
#     REPORT_FILE = ".eze/npmaudit-{self.LANGUAGE_NAME}-report.json"
#
#     [{self.LANGUAGE_NAME}.{NpmOutdatedTool.TOOL_NAME}]
#     REPORT_FILE = ".eze/npmoutdated-{self.LANGUAGE_NAME}-report.json"
#
#     [{self.LANGUAGE_NAME}.{NodeCyclonedxTool.TOOL_NAME}]
#     REPORT_FILE = ".eze/cyclonedx-{self.LANGUAGE_NAME}-bom.json"
# """,
#             "message": """node will require "npm install" ran before running security tools,
# tools are expecting package.json at root level""",
#         }
