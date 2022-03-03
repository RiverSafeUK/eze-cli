# Eze Changelog

## 0.16.0 - 3rd March 2022
Improvements:
- ab-1017: dotnet/c# support
- ab-1043: added html reporter
- ab-1049: added top-level/transitive package support for node

Bug Fixes:
- ab-1007: fixes for github sarif format
- ab-1000: fixes for grype reporter with latest code

## 0.15.0 - 14th February 2022
Improvements:
- ab-1024: terraform/docker multi project support added
- ab-1022: updated docker to deb bullseye + python 3.9
- ab-1027: java multi project support added
- ab-1023: python multi project support added
- ab-1005: default folder for all reports now .eze/
- ab-1006: doc improvements
- ab-979: npm installs are now async (non blocking)

## 0.14.0 - 4th February 2022
Improvements:
- ab-1001: improved auto /ezerc/toml engine
- ab-1001: speeded up trufflehog in docker
- ab-1001: speeded up semgrep in docker
- ab-1001: improved sarif output for github actions

## 0.13.3 - 2nd February 2022
Improvements:
- ab-1002: improved SCA reports (including multi project support)

## 0.13.2 - 2nd February 2022
Improvements:
- ab-998: multi sbom support
- ab-990: updated more efficient eze console report
- ab-996/992: improved github action display

## 0.13.1 - 31th January 2022
Improvements:
- ab-989: adding github action support

## 0.13.0 - 17th January 2022
Improvements:
- ab-720: improved markdown tables
- ab-957: license annotations for python
- ab-620: added license checking
- ab-847: added python unfixed version example
- ab-868: added s3 reporter
- ab-944: added async running, status counts for tools

Bugfixes:
- ab-981: semgrep and npmaduit edge cases
- ab-949: fixed bandit edgecase

## 0.12.0 - 15th December 2021
Improvements:
- ab-898 Graceful errors: failed http calls were crashing cli
- ab-899 Truffle now auto configured to scan all source
- ab-897 Improved console log colours
- ab-945 Cleaned up java tooling / added test case for CVE-2021-4428

Bugfixes:
- ab-912 semgrep powershell console issues

## 0.11.0 - 22th October 2021
Improvements:
- ab-851 : updated python cyclonedx version
- ab-855 : update remotescan automatically run eze reporter

Bugfixes:
- ab-848 : trufflehog warnings with non git repos in ado
- ab-850 : auto run "npm install" when running "npm audit"
- ab-860 : ado pull requests are coming up as branch "merge"
- ab-862 : npmaudit ignore dev dependencies
- ab-887 : cyclonedx node and py cli using same command
- ab-888 : semgrep crashes on windows, handle window as warning not tool exit
- ab-895 : mac support, auto detect python version and pip version in make
- ab-898 : tools non-zero code can crash whole cli

## 0.10.0 - 15th October 2021
Improvements:
- ab-800: improved report format to include tool type and date
- ab-818: added kics tool plugin
- ab-813: added support for v2 reporting console endpoint
- ab-819: sarif reporter plugin

Misc:
- ab-774: move snyk tools into separate plugin

## 0.9.0 - 20th September 2021
Improvements:
- ab-778: improved test coverage
- ab-742: adding new windowslex utils class (single quotes of linux shlex lib breaking windows)
- ab-741 / ab-704: improvement doc readme
- ab-740: removing report files from scans
- ab-688: improved error messages when file not found / os permission errors
- ab-670: simplified trufflehog scan report when large matching text returned

Bugfixes:
- ab-777: fix reports folder error
- ab-771 / ab-712: fix latest trufflehog skip argument / line-numbers changes
- ab-758: fix latest cyclonedx contains breaking changes
- ab-739: eze tools list  - crashes with maven not installed
- ab-724: BUG: WINDOWS : Running "eze test" command locally returns error
  (due to linux shlex ab-742)
- ab-711: fixing image parameter for trivy plugin
- ab-710: fixing minor typos

## 0.8.2 - 4th August 2021
Bugfixes:
- ab-699: exposing more trufflehog flags
- ab-586: Adding shlex protection of cli lib
- ab-605: bug fix for empty json reports from os tools

## 0.8.1 - 28th July 2021
Bugfixes:
- ab-665: Updating docker instructions
- ab-666: improving/fixing ci support

## 0.8.0 - 24th July 2021
Initial Release