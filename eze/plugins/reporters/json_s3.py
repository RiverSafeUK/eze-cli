"""JSON reporter exported to S3 bucket class implementation"""

import json
import click
from eze import __version__
from eze.core.reporter import ReporterMeta
from eze.utils.io import write_json
import boto3
import os
from botocore.exceptions import ClientError


class JsonS3Reporter(ReporterMeta):
    """Python report class for uploading the report results in json format into an S3 bucket"""

    REPORTER_NAME: str = "json-s3"
    SHORT_DESCRIPTION: str = "json file into s3 reporter"
    INSTALL_HELP: str = """inbuilt"""
    MORE_INFO: str = """inbuilt"""
    LICENSE: str = """inbuilt"""
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": "eze_report.json",
            "help_text": """report file location
By default set to eze_report.json""",
        },
        "AWS_ACCESS_KEY": {
            "type": str,
            "default": "",
            "help_text": """aws access key of user authorized to upload files in bucket""",
        },
        "AWS_SECRET_KEY": {
            "type": str,
            "default": "",
            "help_text": """aws secret key of user authorized to upload files in bucket""",
        },
    }

    @staticmethod
    def check_installed() -> str:
        """Method for detecting if reporter installed and ready to run report, returns version installed"""
        return __version__

    async def run_report(self, scan_results: list):
        """Method for taking scans and turning then into report output"""
        json_location = write_json(self.config["REPORT_FILE"], scan_results)
        print(f"written json report : {json_location}")
        self.upload_files(json_location)

    def upload_files(self, json_file: str) -> str:
        """Method for uploading json files into s3 bucket"""
        if not json_file:
            return

        # get credentials from environment or config toml
        access_key = os.environ.get("ACCESS_KEY") or self.config["AWS_ACCESS_KEY"]
        secret_key = os.environ.get("SECRET_KEY") or self.config["AWS_SECRET_KEY"]

        if not access_key or not secret_key:
            small_indent = "    "
            click.echo(f"""{small_indent}No aws credentials provided to upload file into S3 bucket""")
            return

        client = boto3.client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

        try:
            client.put_object(
                Body=str(json_file),
                Bucket="ezemc-reporters",
                Key=os.path.basename(json_file),
            )
            click.echo(f"""{"    "}Json Report file was uploaded successfully""")

        except ClientError as error:
            click.echo(f"""{"    "}Error trying to upload in S3: {error}""", err=True)
