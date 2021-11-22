# Eze Changelog

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