"""Dockerfile Language Runner module"""
import click

from eze.core.enums import SourceType
from eze.core.language import LanguageRunnerMeta
from eze.plugins.tools.anchore_grype import GrypeTool
from eze.plugins.tools.anchore_syft import SyftTool
from eze.plugins.tools.semgrep import SemGrepTool
from eze.plugins.tools.trufflehog import TruffleHogTool
from eze.utils.cli import extract_cmd_version


class DockerRunner(LanguageRunnerMeta):
    """Base class for Docker language runner"""

    LANGUAGE_NAME: str = "docker"
    SOURCE_TYPE: SourceType = SourceType.CONTAINER
    SHORT_DESCRIPTION: str = "Docker (Dockerfile)"
    INSTALL_HELP: str = """"""
    MORE_INFO: str = """Docker Runner
=================================
Scan docker image for sbom and sca analysis
and running secret and semgrep sast on raw Dockerfile

Tips and Tricks
=================================
Once you've built your docker images and have them locally available

Populate DOCKER_TAR_FILE / DOCKER_TAG with your pre-built version

https://docs.docker.com/engine/reference/builder/
"""
    EZE_CONFIG: dict = {
        "SOURCES": {
            "type": list,
            "default": ["Dockerfile"],
            "help_text": """List of files and folders to scan""",
            "help_example": """["Dockerfile"]""",
        },
        "DOCKERFILE": {
            "type": str,
            "help_text": """Location of raw dockerfile""",
        },
        "DOCKER_IMAGE_FILE": {
            "type": str,
            "help_text": """Location of docker image tar (will be used as target if BUILD_DOCKER_TAR_FILE set)""",
        },
        "DOCKER_TAG": {
            "type": str,
            "help_text": """docker tag (will be used as target if BUILD_DOCKER_TAR_FILE set)""",
        },
    }
    FILE_PATTERNS: dict = {"DOCKER_FILE": "Dockerfile$"}
    FOLDER_PATTERNS: dict = {}

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if tool installed and ready to run scan, returns version installed"""
        version = extract_cmd_version("docker --version")
        if not version:
            return "inbuilt (docker: none)"
        return f"inbuilt (docker: {version})"

    async def pre_test(self) -> list:
        """Method for running a pre test builds on project"""
        # AB#662: implement auto docker build
        # aka docker --file=xxx --tag=xxx
        click.echo("Docker auto build not implemented yet, see AB#662: implement auto docker build")

    def create_ezerc(self) -> dict:
        """Method for building a dynamic ezerc.toml fragment"""
        return {
            "fragment": f"""
[{self.LANGUAGE_NAME}]
# Eze Dockerfile codebase
#
# To enable SCA and SBOM, the docker image must be built first
# uncomment DOCKER_TAG and populate image tag
tools = ['{SemGrepTool.TOOL_NAME}', '{TruffleHogTool.TOOL_NAME}']

# DOCKER_TAG: <docker-image-tag>
# tools = ['{SemGrepTool.TOOL_NAME}', '{TruffleHogTool.TOOL_NAME}', '{GrypeTool.TOOL_NAME}', '{SyftTool.TOOL_NAME}']
#    [{self.LANGUAGE_NAME}.{GrypeTool.TOOL_NAME}]
#    REPORT_FILE = "reports/grype-{self.LANGUAGE_NAME}-report.json"
#    [{self.LANGUAGE_NAME}.{SyftTool.TOOL_NAME}]
#    REPORT_FILE = "reports/syft-{self.LANGUAGE_NAME}-report.json"
    [{self.LANGUAGE_NAME}.{SemGrepTool.TOOL_NAME}]
    REPORT_FILE = "reports/semgrep-{self.LANGUAGE_NAME}-report.json"
    CONFIGS = [
        "p/dockerfile"
    ]
    [{self.LANGUAGE_NAME}.{TruffleHogTool.TOOL_NAME}]
    REPORT_FILE = "reports/truffleHog-{self.LANGUAGE_NAME}-report.json"
    SOURCE = "Dockerfile"
    IGNORED_FILES = [
        "node_modules/",
        "target/",
        "build/",
        "dist/",
        ".gradle",
        ".aws",
        ".idea",
        ".pytest_cache"
    ]

""",
            "message": f"""To enable SCA and SBOM against Dockerfile, the docker image must be built first

uncomment DOCKER_TAG and populate image tag
DOCKER_TAG: <docker-image-tag>
then uncomment out the Syft (SBOM) and Grype (SCA) Tools
""",
        }
