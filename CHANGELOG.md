# CHANGELOG

<!-- version list -->

## v1.0.1 (2025-07-08)

### Bug Fixes

- Refresh semantic-release token, hardcode version for auto update
  ([`840054c`](https://gitlab.com/xakepnz/enterpriseattack/-/commit/840054c1776c77a62a9937c8977c677447b20c95))

- Remove deprecated license classifier
  ([`2bc4fd1`](https://gitlab.com/xakepnz/enterpriseattack/-/commit/2bc4fd19208ffb32cd2417965e89e42e05eaf589))

- Remove newline from pyproject description
  ([`4e78087`](https://gitlab.com/xakepnz/enterpriseattack/-/commit/4e78087e00adde7453d539833a8efcb2cb368460))

- Update license-files syntax
  ([`b5120b9`](https://gitlab.com/xakepnz/enterpriseattack/-/commit/b5120b95fb7325b7e11096de11871eaaa1c3e649))

- Version pin to 1.0.0
  ([`f9de500`](https://gitlab.com/xakepnz/enterpriseattack/-/commit/f9de500aa25a472bdf0b72b6aa53a5b976ebbb4a))


## v1.0.0 (2025-07-07)

- Refactored ci config, added pyproject.toml, updated license (year), added pre-commit

## v0.1.8 (2023-01-12)

### Bug-fixes:

- Deprecated Techniques without sub techniques raised TypeError exception (#18) - [e04aa5f](https://github.com/xakepnz/enterpriseattack/commit/e04aa5fa6f5bd29a5c270a4abcc7384e2a3a2eb7)

### Features:

- Add sub_techniques property to Tactics class (#19) - [ff556f6](https://github.com/xakepnz/enterpriseattack/commit/ff556f655486061ccfeafd87d2da7d6c98e6f1b0)
- Add sub_techniques property to Data Source class (#20) - [4de4b36](https://github.com/xakepnz/enterpriseattack/commit/4de4b3621ffadc3d9f0b762e8ee3df8340dbae4e)
- Add sub_techniques property to Software class (#21) - [9d4b5fc](https://github.com/xakepnz/enterpriseattack/commit/9d4b5fc5231e36f5aacfcf2de0add0398483f919)
- Change how techniques are appended (exclude sub techniques) in Software class (#21) - [9d4b5fc](https://github.com/xakepnz/enterpriseattack/commit/9d4b5fc5231e36f5aacfcf2de0add0398483f919)

## v0.1.7 (2022-12-28)

- Added sub_techniques property to Group objects (#14) - 29232d2
  - It was discovered in #14 that Group objects did not have the sub_techniques property available.
- Added test for group sub_techniques iterations (#14) - a94394d

## v0.1.6 (2022-12-19)

- Alter the GitHub templates (#7) - 327b98d
- Add more tests for code coverage (#9) - 380cec3
- Implement MITRE ATT&CK campaigns (#8) - 1f5630e
- Add software & groups to campaigns (#8) - cc9a6f9
- Create Subscriptable objects in the main Attack class (#6) - c99c712
- Allow users to hardcode MITRE ATT&CK data versioning (#5) - d7b5318

## v0.1.5 (2022-03-14)

- PEP8 Standardized codebase fixed errors on lint
- Fixed Travis typos

## v0.1.4 (2022-03-13)

- Cleaned up code line lengths
- Fixed techniques mitigations
- Ordered imports by type
- Created component.py with Component class separate to Data source
- Added tools & malware & software & components to techniques
- Added tools & malware & tactics to groups
- Added tools & malware & software & components & tactics to sub_techniques
- Added tactics to software
- Added tactics to mitigations
- Created Code build tests with Travis CI
- Added tactics & techniques to components

## v0.1.3 (2022-03-11)

- Converted format strings to f strings for readability/speed.
- Updated README.md with more examples
- Allow proxy args to Attack() for proxy-passing.

## v0.1.2 (2021-12-04)

- Fixed issue: https://github.com/xakepnz/enterpriseattack/issues/1
- Issue related to all sub techniques being grouped under each technique, instead of relevant sub techniques.
- Fixed typo with ReadMe Documentation link

## v0.1.1 (2022-11-03)

- Initial Release
