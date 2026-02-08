# Changelog

All notable changes to DeployGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Clean Architecture refactoring with Domain, Application, and Infrastructure layers
- Outbox Pattern for reliable event publishing
- Domain events for audit and integration

### Changed
- Migrated message broker from Redis to RabbitMQ
- Improved error handling with domain-specific exceptions

---

## [0.1.6] - 2026-02-01

### Added
- **Verified Secrets**: Test if detected secrets are actually active (like truffleHog)
- Support for 40+ services verification including GitHub, Stripe, OpenAI, Slack
- `deployguard verify` command with `--only-active` and `--only-inactive` flags
- JSON and table output formats for verification results

### Changed
- Improved pattern matching performance with pre-compiled regex
- Better error messages for authentication failures

### Fixed
- False positives for AWS example keys
- Unicode handling in secret values

---

## [0.1.5] - 2026-01-15

### Added
- **Pre-commit hook**: Block commits containing secrets
- `deployguard hooks install/status/test/uninstall` commands
- Pre-commit framework integration support
- `.deployguardignore` file support

### Changed
- Faster staged file scanning for pre-commit hook
- Improved CLI output with colors and emojis

---

## [0.1.4] - 2026-01-01

### Added
- **Auto-remediation**: Replace hardcoded secrets with environment variables
- Language-aware code modification (Python, JavaScript, Go, Java, Bash)
- `.env` file generation from detected secrets
- `deployguard remediate auto --preview` and `--execute` commands

### Changed
- Refactored core scanner for better extensibility
- Improved finding deduplication

---

## [0.1.3] - 2025-12-15

### Added
- **Git history scanning**: Scan entire repository history
- **Git history cleaning**: Remove secrets from all commits
- Integration with git-filter-repo for safe history rewriting
- `--include-history` flag for scan command
- `deployguard clean history` command

### Fixed
- Memory issues when scanning large repositories
- Handling of binary files

---

## [0.1.2] - 2025-12-01

### Added
- **961 detection patterns**: Industry-leading coverage
- Patterns for AI/ML services (OpenAI, Anthropic, HuggingFace)
- Patterns for cloud providers (AWS, GCP, Azure, DigitalOcean)
- Entropy-based detection for unknown secret formats
- Custom patterns via YAML configuration

### Changed
- Pattern file format updated to YAML
- Improved severity classification

---

## [0.1.1] - 2025-11-15

### Added
- **REST API**: FastAPI-based API for integration
- `/api/v1/scan` endpoint for remote scanning
- `/api/v1/providers` for listing supported platforms
- Docker and docker-compose support
- Kubernetes deployment manifests

### Changed
- CLI refactored to use shared core services
- Better logging and debugging output

---

## [0.1.0] - 2025-11-01

### Added
- Initial release
- CLI tool with `scan`, `auth`, and `report` commands
- GitHub and Bitbucket platform support
- Local directory and file scanning
- JSON and CSV export formats
- Basic secret detection patterns (150+)

---

## Version History Summary

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.6 | 2026-02-01 | Verified Secrets (40+ services) |
| 0.1.5 | 2026-01-15 | Pre-commit hooks |
| 0.1.4 | 2026-01-01 | Auto-remediation |
| 0.1.3 | 2025-12-15 | Git history scanning/cleaning |
| 0.1.2 | 2025-12-01 | 961 detection patterns |
| 0.1.1 | 2025-11-15 | REST API |
| 0.1.0 | 2025-11-01 | Initial release |

---

[Unreleased]: https://github.com/salginci/deployguard_repository_cleaner/compare/v0.1.6...HEAD
[0.1.6]: https://github.com/salginci/deployguard_repository_cleaner/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/salginci/deployguard_repository_cleaner/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/salginci/deployguard_repository_cleaner/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/salginci/deployguard_repository_cleaner/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/salginci/deployguard_repository_cleaner/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/salginci/deployguard_repository_cleaner/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/salginci/deployguard_repository_cleaner/releases/tag/v0.1.0
