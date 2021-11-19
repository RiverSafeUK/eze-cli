"""Networking helpers
"""
import json
import urllib.request
import urllib.error
from json import JSONDecodeError
from eze.utils.error import EzeNetworkingError


def request_json(url: str, data=None, headers={}, method=None) -> dict:
    """
    requests a url and convert return into json

    :raises EzeNetworkingError: on networking error or json decoding error"""
    contents = request(url, data=data, headers=headers, method=method)
    try:
        return json.loads(contents)
    except JSONDecodeError as error:
        raise EzeNetworkingError(f"Error in JSON response '{url}', {contents} ({error})")


def request(url: str, data=None, headers={}, method=None) -> str:
    """
    requests a url and returns string

    :raises EzeNetworkingError: on networking error
    """
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        # nosec: Request is being built directly above as a explicit http request
        # hence no risk of unexpected scheme
        with urllib.request.urlopen(req) as stream:  # nosec # nosemgrep
            return stream.read()

    except urllib.error.HTTPError as error:
        error_text = error.read().decode()
        error_message = f"{error.code} ({error.reason} [{error_text}]"

        raise EzeNetworkingError(f"Error accessing url '{url}', Error: {error_message}")
    except urllib.error.URLError as error:
        raise EzeNetworkingError(f"Error accessing url '{url}', Error: {error}")
