"""JSON reporter exported to S3 bucket class implementation"""

import os
from datetime import datetime

import boto3
from botocore.exceptions import ClientError
from botocore.client import Config
from pydash import py_

from eze.core.reporter import ReporterMeta
from eze.utils.io.print import pretty_print_json
from eze.utils.git import get_active_branch_name, get_active_branch_uri
from eze.utils.log import log, log_error
from eze.utils.io.http import spine_case_url


class S3Reporter(ReporterMeta):
    """Python report class for uploading the report results in json format into an S3 bucket

    uses boto3 AWS library
    https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html#configuration"""

    REPORTER_NAME: str = "s3"
    SHORT_DESCRIPTION: str = "s3 uploader reporter"
    INSTALL_HELP: str = """inbuilt"""
    MORE_INFO: str = """S3 reporters uses the boto3 library

Configure your AWS credentials as you would for other boto3 products, such as the AWS cli

shared credentials location: ~/.aws/credentials

more details:
https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html#configuration
https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
"""
    LICENSE: str = """inbuilt"""
    VERSION_CHECK: dict = {"FROM_EZE": True}
    EZE_CONFIG: dict = {
        "BUCKET_NAME": {
            "type": str,
            "help_example": "ezemc-reporters",
            "required": True,
            "help_text": """name of s3 bucket to upload the json report""",
        },
        "OBJECT_KEY": {
            "type": str,
            "default": None,
            "default_help_value": "<GIT_NAME>-<BRANCH_NAME>-<YYYY>-<MM>-<DD>-eze-report.json",
            "required": False,
            "help_text": """object key used to store the report json in s3 bucket""",
        },
    }

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output"""
        self.upload_object(scan_results)

    def upload_object(self, value: any):
        """Method for uploading json files into s3 bucket"""
        pretty_json = pretty_print_json(value)
        region_name = os.environ.get("AWS_REGION", "eu-west-1")
        client = boto3.client(
            "s3",
            region_name=region_name,
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY"),
            aws_secret_access_key=os.environ.get("AWS_SECRET_KEY"),
            config=Config(signature_version="s3v4"),
            endpoint_url=f"https://s3.{region_name}.amazonaws.com",
        )
        bucket = self.config["BUCKET_NAME"]
        key = self.config["OBJECT_KEY"]
        try:
            client.put_object(
                Body=pretty_json,
                Bucket=bucket,
                Key=key,
            )
            log(f"""Json Report file was uploaded successfully""")
        except ClientError as error:
            region = py_.get(client, "meta.region_name")
            account = boto3.client("sts").get_caller_identity().get("Account")
            log_error(f"Error trying to upload '({region}:{account}){bucket}:{key}' into S3: {error}")

    def _parse_config(self, eze_config: dict) -> dict:
        """take raw config dict and normalise values"""
        parsed_config = super()._parse_config(eze_config)

        # ADDITION PARSING: OBJECT_KEY
        # if not given, set to <GIT_NAME>-<BRANCH_NAME>-eze-report.json
        if not parsed_config["OBJECT_KEY"]:
            git_dir = os.getcwd()
            uri = spine_case_url(get_active_branch_uri(git_dir) or "unknown-repo")
            branch = spine_case_url(get_active_branch_name(git_dir) or "unknown-branch")
            parsed_config["OBJECT_KEY"] = f"{uri}-{branch}-{datetime.now().strftime('%Y-%m-%d')}-eze-report.json"

        return parsed_config
