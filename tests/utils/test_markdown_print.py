# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from eze.utils.markdown_print import print_scan_results_as_markdown
from tests.__fixtures__.fixture_helper import load_json_fixture
from tests.__test_helpers__.mock_helper import unmock_print, mock_print
from eze.core.tool import ScanResult


def test_print_scan_results_as_markdown__empty() -> str:
    # Given
    test_input = []
    expected_output = """
# Eze Report Results


## Summary  ![tools](https://img.shields.io/static/v1?style=plastic&label=Tools&message=0&color=blue)
---


![critical](https://img.shields.io/static/v1?style=plastic&label=critical&message=0&color=red)
![high](https://img.shields.io/static/v1?style=plastic&label=high&message=0&color=orange)
![medium](https://img.shields.io/static/v1?style=plastic&label=medium&message=0&color=yellow)
![low](https://img.shields.io/static/v1?style=plastic&label=low&message=0&color=lightgrey)



<b>Tools executed: 0</b>



"""

    # When
    output = print_scan_results_as_markdown(test_input)

    # Then
    assert output == expected_output


def test_print_scan_results_as_markdown() -> str:
    # Given
    scan_results_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_scan_result.json")
    input_scan_results: list = [ScanResult(scan_result) for scan_result in scan_results_fixture]

    output = print_scan_results_as_markdown(input_scan_results)
    expected_output = """
# Eze Report Results


## Summary  ![tools](https://img.shields.io/static/v1?style=plastic&label=Tools&message=1&color=blue)
---


![critical](https://img.shields.io/static/v1?style=plastic&label=critical&message=0&color=red)
![high](https://img.shields.io/static/v1?style=plastic&label=high&message=0&color=orange)
![medium](https://img.shields.io/static/v1?style=plastic&label=medium&message=0&color=yellow)
![low](https://img.shields.io/static/v1?style=plastic&label=low&message=0&color=lightgrey)



<b>Tools executed: 1</b>
* Safety (unknown)


## Errors
---


### [safety] Errors
Executable not found 'semgrep', when running command semgrep --optimizations all --json --time --disable-metrics -q -c p/ci -c p/nodejs -o reports/semgrep-node-report.json --exclude tests --exclude reports/truffleHog-node-report.json --exclude reports/semgrep-node-report.json --exclude reports/npmaudit-node-report.json --exclude reports/npmoutdated-node-report.json --exclude reports/cyclonedx-node-bom.json --exclude eze_bom.json --exclude eze_report.json --exclude eze_junit_report.xml

## Vulnerabilities
---


### [safety] Vulnerabilities


**[MEDIUM DEPENDENCY] : dependency-pip-medium-with-cve (1.3.0)**


**overview**: The mirroring support (-M, --use-mirrors) in Python Pip before 1.5 uses insecure DNS querying and authenticity checks which allows attackers to perform man-in-the-middle attacks.


CVE: CVE-2013-5123

**recommendation**: Update pip (1.3.0), vulnerable versions: <1.5






**[MEDIUM DEPENDENCY] : dependency-ignored-pip (1.3.0)**


**overview**: The resolve_redirects function in sessions.py in requests 2.1.0 through 2.5.3 allows remote attackers to conduct session fixation attacks via a cookie without a host value in a redirect. <a href="http://cwe.mitre.org/data/definitions/384.html">CWE-384: Session Fixation</a>




**recommendation**: Update pip (1.3.0), vulnerable versions: <6.1.0







## Warnings
---


### [safety] Warnings
Warning: unpinned requirement 'blackduck' found in C:/dev/repos/sacbdnotify/requirements.txt, unable to check.
Warning: unpinned requirement 'click' found in tests-integration/__fixture__/python/requirements.txt, unable to check.
"""

    print(output)
    assert output == expected_output
