"""Lists out the inbuilt plugins in Eze"""
from eze.plugins.languages.docker import DockerRunner
from eze.plugins.languages.java import JavaRunner
from eze.plugins.languages.node import NodeRunner
from eze.plugins.languages.python import PythonRunner
from eze.plugins.reporters.bom import BomReporter
from eze.plugins.reporters.bom_formatted import BomFormattedReporter
from eze.plugins.reporters.console import ConsoleReporter
from eze.plugins.reporters.eze import EzeReporter
from eze.plugins.reporters.json import JsonReporter
from eze.plugins.reporters.s3 import S3Reporter
from eze.plugins.reporters.junit import JunitReporter
from eze.plugins.reporters.quality import QualityReporter
from eze.plugins.reporters.sarif import SarifReporter
from eze.plugins.tools.anchore_grype import GrypeTool
from eze.plugins.tools.anchore_syft import SyftTool
from eze.plugins.tools.container_trivy import TrivyTool
from eze.plugins.tools.gitleaks import GitLeaksTool
from eze.plugins.tools.java_cyclonedx import JavaCyclonedxTool
from eze.plugins.tools.java_dependencycheck import JavaDependencyCheckTool
from eze.plugins.tools.java_spotbugs import JavaSpotbugsTool
from eze.plugins.tools.node_cyclonedx import NodeCyclonedxTool
from eze.plugins.tools.node_npmaudit import NpmAuditTool
from eze.plugins.tools.node_npmoutdated import NpmOutdatedTool
from eze.plugins.tools.python_bandit import BanditTool
from eze.plugins.tools.python_cyclonedx import PythonCyclonedxTool
from eze.plugins.tools.python_piprot import PiprotTool
from eze.plugins.tools.python_safety import SafetyTool
from eze.plugins.tools.raw import RawTool
from eze.plugins.tools.semgrep import SemGrepTool
from eze.plugins.tools.trufflehog import TruffleHogTool
from eze.plugins.tools.checkmarx_kics import KicsTool


def get_languages() -> dict:
    """Return the default language runners that are installed"""
    return {
        "java": JavaRunner,
        "python": PythonRunner,
        "node": NodeRunner,
        "docker": DockerRunner,
    }


def get_reporters() -> dict:
    """Return the default reporters engines that are installed"""
    return {
        "console": ConsoleReporter,
        "json": JsonReporter,
        "s3": S3Reporter,
        "junit": JunitReporter,
        "quality": QualityReporter,
        "eze": EzeReporter,
        "bom": BomReporter,
        "bom-formatted": BomFormattedReporter,
        "sarif": SarifReporter,
    }


def get_tools() -> dict:
    """Return the default tools that are installed"""
    return {
        # Generic Tools
        "raw": RawTool,
        "trufflehog": TruffleHogTool,
        "semgrep": SemGrepTool,
        "anchore-grype": GrypeTool,
        "anchore-syft": SyftTool,
        "gitleaks": GitLeaksTool,
        # Java Tools
        "java-cyclonedx": JavaCyclonedxTool,
        "java-dependencycheck": JavaDependencyCheckTool,
        "java-spotbugs": JavaSpotbugsTool,
        # Python Tools
        "python-safety": SafetyTool,
        "python-piprot": PiprotTool,
        "python-bandit": BanditTool,
        "python-cyclonedx": PythonCyclonedxTool,
        # Node Tools
        "node-npmaudit": NpmAuditTool,
        "node-npmoutdated": NpmOutdatedTool,
        "node-cyclonedx": NodeCyclonedxTool,
        # Container Tools
        "container-trivy": TrivyTool,
        "kics": KicsTool,
    }
