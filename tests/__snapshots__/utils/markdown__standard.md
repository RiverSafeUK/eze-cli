
# Eze Report Results

## Summary  ![tools](https://img.shields.io/static/v1?style=plastic&label=Tools&message=1&color=blue)

---


![critical](https://img.shields.io/static/v1?style=plastic&label=critical&message=0&color=red)
![high](https://img.shields.io/static/v1?style=plastic&label=high&message=0&color=orange)
![medium](https://img.shields.io/static/v1?style=plastic&label=medium&message=0&color=yellow)
![low](https://img.shields.io/static/v1?style=plastic&label=low&message=0&color=lightgrey)



<b>Tools executed:</b>&nbsp;1


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
* Warning: unpinned requirement 'blackduck' found in C:/dev/repos/sacbdnotify/requirements.txt, unable to check.
  Warning: unpinned requirement 'click' found in tests-integration/__fixture__/python/requirements.txt, unable to check.