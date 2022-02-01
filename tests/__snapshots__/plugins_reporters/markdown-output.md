
# Eze Report Results


## Summary  ![tools](https://img.shields.io/static/v1?style=plastic&label=Tools&message=1&color=blue)
---


![critical](https://img.shields.io/static/v1?style=plastic&label=critical&message=0&color=red)
![high](https://img.shields.io/static/v1?style=plastic&label=high&message=0&color=orange)
![medium](https://img.shields.io/static/v1?style=plastic&label=medium&message=1&color=yellow)
![low](https://img.shields.io/static/v1?style=plastic&label=low&message=1&color=lightgrey)
            
<b>Tools executed: </b>

* Safety (unknown)
            

## Vulnerabilities
---


    [safety] Vulnerabilities
    =================================
    TOOL REPORT: safety (scan duration: 1.6 seconds)
        total: 3 (medium:1, low:1, na:1, warnings:true)
        ignored: 1 (medium:1, warnings:true)

        [MEDIUM DEPENDENCY] : dependency-pip-medium-with-cve (1.3.0)
        overview: The mirroring support (-M, --use-mirrors) in Python Pip before 1.5 uses insecure DNS querying and authenticity checks which allows attackers to perform man-in-the-middle attacks.
        CVE: CVE-2013-5123
        recommendation: Update pip (1.3.0), vulnerable versions: <1.5

        [NA DEPENDENCY] : dependency-na-pip-no-cve (1.3.0)
        overview: The pip package before 19.2 for Python allows Directory Traversal when a URL is given in an install command, because a Content-Disposition header can have ../ in a filename, as demonstrated by overwriting the /root/.ssh/authorized_keys file. This occurs in _download_http_url in _internal/download.py.
        recommendation: Update pip (1.3.0), vulnerable versions: <19.2

        [MEDIUM DEPENDENCY] : dependency-ignored-pip (1.3.0)
        overview: The resolve_redirects function in sessions.py in requests 2.1.0 through 2.5.3 allows remote attackers to conduct session fixation attacks via a cookie without a host value in a redirect. <a href="http://cwe.mitre.org/data/definitions/384.html">CWE-384: Session Fixation</a>
        recommendation: Update pip (1.3.0), vulnerable versions: <6.1.0

        [HIGH SECRET] : Found Hardcoded 'Password in URL' Pattern
        overview: Found Hardcoded 'Password in URL' Pattern in __fixture__\secrets\all_the_hard_coded_secrets.py
        recommendation: Investigate
         __fixture__\secrets\all_the_hard_coded_secrets.py
         Line 1 for 'Password in URL' strings
         Full Match: 1 SERVER_LOCATION =
         https://username:password@localhost:1234
        file: __fixture__\secrets\all_the_hard_coded_secrets.py (line 1)


## Warnings
---

    [safety] Warnings
    =================================
    Warning: unpinned requirement 'blackduck' found in C:/dev/repos/sacbdnotify/requirements.txt, unable to check.
    Warning: unpinned requirement 'click' found in tests-integration/__fixture__/python/requirements.txt, unable to check.
    
