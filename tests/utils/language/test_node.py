from unittest import mock

import pytest

from eze.utils.cli.run import CompletedProcess

from tests.__fixtures__.fixture_helper import convert_to_std_object
from eze.utils.language.node import (
    annotate_transitive_licenses,
)

TRANSITIVE_PACKAGE_STDOUT = """{
  "name": "eze-console",
  "version": "0.12.0",
  "problems": [
    "peer dep missing: react@^16.6.3, required by react-charts@2.0.0-beta.7",
    "peer dep missing: react-native@>=0.56, required by react-native-get-random-values@1.7.2"
  ],
  "dependencies": {
    "@aws-amplify/ui-components": {
      "version": "1.9.6",
      "from": "@aws-amplify/ui-components@1.9.6",
      "resolved": "https://registry.npmjs.org/@aws-amplify/ui-components/-/ui-components-1.9.6.tgz",
      "dependencies": {
      }
    },
    "redux-thunk": {
      "version": "2.4.1",
      "from": "redux-thunk@2.4.1",
      "resolved": "https://registry.npmjs.org/redux-thunk/-/redux-thunk-2.4.1.tgz"
    }
  }
}
"""


@pytest.mark.asyncio
@mock.patch("eze.utils.language.node.run_async_cmd")
async def test_annotate_transitive_licenses(mocked_run_cmd):
    # Given
    input_sbom = {
        "...": "...",
        "metadata": {"...": "..."},
        "components": [
            {"name": "@aws-amplify/ui-components"},
            {"name": "redux-thunk"},
            {"name": "jest"},
            {"name": "redux-sub-dependency"},
        ],
    }
    mocked_run_cmd.return_value = CompletedProcess(TRANSITIVE_PACKAGE_STDOUT, "")
    expected_output = {
        "...": "...",
        "metadata": {"...": "..."},
        "components": [
            {"name": "@aws-amplify/ui-components", "properties": {"transitive": False}},
            {"name": "redux-thunk", "properties": {"transitive": False}},
            {"name": "jest", "properties": {"transitive": True}},
            {"name": "redux-sub-dependency", "properties": {"transitive": True}},
        ],
    }
    # When
    await annotate_transitive_licenses(input_sbom, "some_cwd/", False)
    # Then
    assert convert_to_std_object(input_sbom) == expected_output
