# Introduction
All notable changes to this project will be documented in this file.

The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2021-05-07
### Added
- Secure compare function to mitigate timing attack.

## [0.2.0] - 2021-02-04
### Changed
- Rename library in `pkcs5`
- Remove testing hex encoding module.
- Export shortcut functions in `pkcs5` module.
- Update documentation.
- Format code with new style.

### Fixed
- Hardcoded `sha512` digest in `pkcs:pbkdf2/4` function.

## [0.1.0] - 2020-12-17
### Added
- PBKDF2 algorithm.
