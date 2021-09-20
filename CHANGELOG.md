# Eze Changelog

## 0.9.0
Improvements:
- ab-778: improved test coverage
- ab-742: adding new windowslex utils class (single quotes of linux shlex lib breaking windows)
- ab-741 / ab-704: improvement doc readme
- ab-740: removing report files from scans
- ab-688: improved error messages when file not found / os permission errors
- ab-670: simplified trufflehog scan report when large matching text returned

Bugs
- ab-777: fix reports folder error
- ab-771 / ab-712: fix latest trufflehog skip argument / line-numbers changes
- ab-758: fix latest cyclonedx contains breaking changes
- ab-739: eze tools list  - crashes with maven not installed
- ab-724: BUG: WINDOWS : Running "eze test" command locally returns error
  (due to linux shlex ab-742)
- ab-711: fixing image parameter for trivy plugin
- ab-710: fixing minor typos

## 0.8.2
Security Release

- ab-699: exposing more trufflehog flags
- ab-586: Adding shlex protection of cli lib
- ab-605: bug fix for empty json reports from os tools

## 0.8.1
Bug Fix Release

- ab-665: Updating docker instructions
- ab-666: improving/fixing ci support

## 0.8.0
Initial Release