


# DuskProbe Contribution Guidelines

**Version**: 4.2\
**Last Updated**: May 08, 2025\
**Description**: This document outlines the guidelines for contributing to DuskProbe, a professional web vulnerability scanner. It covers the contribution process, coding standards, testing requirements, and best practices to ensure high-quality, secure contributions.

## 1. Contribution Overview

DuskProbe welcomes contributions including bug fixes, feature enhancements, plugin development, documentation improvements, and performance optimizations. All contributions must align with the project’s goals of security, performance, and reliability.

### 1.1 Types of Contributions
- **Code**:
  - Bug fixes for existing components (e.g., `VulnerabilityScanner`, `Web3Auditor`).
  - New features (e.g., OAuth2 support, WebSocket scanning).
  - Performance optimizations (e.g., Bloom filter tuning).
- **Plugins**:
  - New vulnerability checks or analysis modules in `plugins/`.
- **Documentation**:
  - Updates to `README.md`, `DuskProbe_Documentation.md`, or inline docstrings.
  - New guides or examples.
- **Tests**:
  - Unit, integration, or security tests for existing or new features.
- **Issues**:
  - Bug reports or feature requests with detailed reproductions.

### 1.2 Contribution Principles
- **Security First**: Contributions must not introduce vulnerabilities or weaken existing security measures.
- **Modularity**: Code should be modular, reusable, and align with existing class structures.
- **Ethical Standards**: Contributions must support ethical scanning (e.g., respect `robots.txt`).
- **Quality**: Code must be well-tested, documented, and maintainable.

## 2. Getting Started

### 2.1 Prerequisites
- **Python**: 3.8+.
- **Dependencies**:
  ```bash
  pip install aiohttp requests stem web3 scikit-learn scapy pybloom-live cryptography colorama fake-useragent beautifulsoup4 pytest
  sudo apt install tor
  ```
- **Tools**:
  - Git for version control.
  - Pylint for linting.
  - pytest for testing.
- **Environment**:
  - Use a virtual environment (`python -m venv venv; source venv/bin/activate`).
  - Clone the repository: `git clone <repository_url>`.

### 2.2 Setting Up the Development Environment
1. **Fork and Clone**:
   - Fork the DuskProbe repository on the hosting platform (e.g., GitHub).
   - Clone your fork: `git clone https://<your-username>/<repository>.git`.
2. **Create Directories**:
   ```bash
   mkdir -p plugins reports config
   chmod 700 plugins reports config
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   If no `requirements.txt` exists, use the command from Prerequisites.
4. **Verify Setup**:
   ```bash
   python DuskProbe.py --help
   ```
   Ensure the CLI displays without errors.

## 3. Contribution Process

### 3.1 Finding or Creating Issues
- **Check Existing Issues**:
  - Review the issue tracker for open bugs or feature requests.
  - Avoid duplicating issues; comment on existing ones if relevant.
- **Create New Issues**:
  - Use the issue template (if provided) or include:
    - **Title**: Clear, concise description (e.g., “XSS Payload False Positive in VulnerabilityScanner”).
    - **Description**: Detailed explanation, including reproduction steps, expected behavior, and actual behavior.
    - **Environment**: Python version, OS, dependency versions.
    - **Priority**: Bug (critical/high/medium/low) or feature request.
  - Assign yourself or request assignment if you plan to work on it.

### 3.2 Branching and Commits
- **Branch Naming**:
  - Use descriptive names: `feature/<issue-id>-description`, `bugfix/<issue-id>-description`, or `docs/<description>`.
  - Example: `feature/123-oauth2-support`, `bugfix/456-xss-false-positive`.
- **Commits**:
  - Write clear, concise commit messages:
    - Start with a verb (e.g., “Add”, “Fix”, “Update”).
    - Reference issue number: “Fix XSS payload parsing (#456)”.
    - Example: “Add OAuth2 support to SessionManager (#123)”.
  - Keep commits atomic (one logical change per commit).
  - Sign commits with GPG if required by the repository.

### 3.3 Pull Request (PR) Submission
- **Create a PR**:
  - Push your branch: `git push origin <branch-name>`.
  - Open a PR against the `main` branch of the upstream repository.
  - Use the PR template (if provided) or include:
    - **Title**: Match the issue or describe the change (e.g., “Add OAuth2 Authentication (#123)”).
    - **Description**: Summarize changes, link to issue, and explain impact.
    - **Checklist**:
      - Code follows coding standards.
      - Tests added/updated and passing.
      - Documentation updated (docstrings, README, etc.).
      - Security implications assessed (e.g., no new vulnerabilities).
- **Review Process**:
  - Expect feedback within 5-7 days.
  - Address reviewer comments promptly and push updates to the same branch.
  - At least one maintainer approval is required for merging.
- **Merge**:
  - Maintainers will squash or rebase commits for a clean history.
  - Delete the branch after merging unless needed for future work.

## 4. Coding Standards

### 4.1 General Guidelines
- **Style**: Follow PEP 8, enforced via Pylint (`pylint DuskProbe.py`).
  - Max line length: 100 characters.
  - Use 4-space indentation.
  - Use single quotes for strings unless double quotes are required.
- **Naming**:
  - Classes: `CamelCase` (e.g., `QuantumEncryptor`).
  - Functions/Methods: `snake_case` (e.g., `scan_url`).
  - Variables: `snake_case`, descriptive (e.g., `max_threads`).
  - Constants: `UPPER_SNAKE_CASE` (e.g., `REQUEST_TIMEOUT`).
- **Type Hints**: Use Python type annotations for all functions and methods (e.g., `def fetch(url: str) -> Optional[str]`).
- **Error Handling**:
  - Use specific exceptions (e.g., `ValueError`, `aiohttp.ClientError`).
  - Log errors with `logger.error` and include context.
  - Avoid bare `except` clauses.

### 4.2 Security Requirements
- **Input Validation**:
  - Validate all user inputs (URLs, file paths, JSON configs) with regex or schema checks.
  - Example: `re.match(r'^https?://', url)` for URLs.
- **File Operations**:
  - Set permissions explicitly: `os.chmod(path, 0o600)` for files, `0o700` for directories.
  - Use context managers (`with open(...) as f`) for file handling.
- **Network Requests**:
  - Use `aiohttp` for asynchronous requests; `requests` for synchronous with retries.
  - Sanitize headers to prevent injection (e.g., no user-controlled values in `User-Agent`).
  - Respect rate limits with `Retry-After` handling.
- **Plugins**:
  - Implement a `run` method returning `Dict` with `type`, `severity`, and `details`.
  - Avoid system-level operations (`os`, `subprocess`, `socket`).
  - Include HMAC signature in `config/encryption.json`.
- **Encryption**:
  - Use `QuantumEncryptor` for sensitive data (e.g., reports, configs).
  - Avoid hardcoding keys; use `os.getenv` or `encryption.json`.

### 4.3 Documentation
- **Docstrings**:
  - Use Google style for all classes, methods, and functions.
  - Example:
    ```python
    def scan_url(self, url: str) -> None:
        """Scan a single URL for vulnerabilities.

        Args:
            url: The URL to scan (e.g., https://example.com).

        Raises:
            ValueError: If the URL is invalid.
        """
    ```
- **Inline Comments**:
  - Explain complex logic or non-obvious decisions.
  - Example: `# Renew Tor circuit every 300s to maintain anonymity`.
- **External Docs**:
  - Update `README.md` or `DuskProbe_Documentation.md` for new features or changes.
  - Include usage examples for new CLI options or plugins.

## 5. Testing Requirements

### 5.1 Test Types
- **Unit Tests**:
  - Cover individual methods (e.g., `QuantumEncryptor.encrypt`, `Config._load_plugins`).
  - Use `pytest` with mocks for external dependencies (e.g., `aiohttp`, `stem`).
- **Integration Tests**:
  - Test interactions between components (e.g., `DuskProbe.scan_url` with `AdvancedScanner`).
  - Use test servers like `http://testphp.vulnweb.com`.
- **Security Tests**:
  - Test for injection vulnerabilities (e.g., malformed URLs, JSON configs).
  - Verify plugin signature validation and dangerous code rejection.
- **Performance Tests**:
  - Measure scan time and memory usage for large sites (`--crawl-depth 5`).
  - Monitor Bloom filter capacity warnings.

### 5.2 Writing Tests
- **Location**: `tests/` directory (create if missing).
- **Naming**: `test_<module>.py` (e.g., `test_vulnerability_scanner.py`).
- **Structure**:
  ```python
  import pytest
  from DuskProbe import QuantumEncryptor

  def test_encryptor():
      enc = QuantumEncryptor("test_key")
      data = "test"
      encrypted = enc.encrypt(data)
      assert enc.decrypt(encrypted) == data
  ```
- **Mocks**:
  - Use `pytest-mock` for network requests or file operations.
  - Example: Mock `aiohttp.ClientSession.get` to return a test response.
- **Coverage**:
  - Aim for >80% coverage (`pytest --cov=DuskProbe`).
  - Exclude third-party dependencies and CLI parsing.

### 5.3 Running Tests
```bash
pytest tests/ --cov=DuskProbe --cov-report=html
```
- Fix any failures before submitting a PR.
- Include test results in the PR description if coverage changes significantly.

## 6. Plugin Development

### 6.1 Structure
- **Location**: `plugins/`.
- **Naming**: `plugin_<name>.py` (e.g., `plugin_oauth2.py`).
- **Template**:
  ```python
  class Plugin:
      def run(self, url: str) -> Dict:
          """Run the plugin on a URL.

          Args:
              url: The URL to scan.

          Returns:
              Dict with type, severity, and details.
          """
          return {
              "type": "OAUTH2_CHECK",
              "severity": "INFO",
              "details": f"Checked OAuth2 for {url}"
          }
  ```

### 6.2 Security
- **Validation**:
  - Generate SHA256 hash: `hashlib.sha256(open('plugin_name.py', 'rb').read()).hexdigest()`.
  - Compute HMAC:
    ```python
    import hmac, hashlib
    file_hash = "<sha256_hash>"
    hmac_key = "<hmac_key_from_encryption.json>"
    print(hmac.new(hmac_key.encode(), file_hash.encode(), hashlib.sha256).hexdigest())
    ```
  - Add to `config/encryption.json`:
    ```json
    {
      "plugin_signatures": {
        "plugin_oauth2.py": "<hmac_signature>"
      }
    }
    ```
- **Restrictions**:
  - No direct file or network access; use `SessionManager` or `AdvancedSession`.
  - Avoid dangerous modules (`os`, `subprocess`, `socket`).

### 6.3 Testing
- Write unit tests in `tests/test_plugins.py`.
- Example:
  ```python
  def test_oauth2_plugin():
      from plugins.plugin_oauth2 import Plugin
      plugin = Plugin()
      result = plugin.run("https://example.com")
      assert result["type"] == "OAUTH2_CHECK"
  ```

## 7. Best Practices

### 7.1 Code Quality
- **Linting**: Run `pylint DuskProbe.py` and fix warnings (score >8/10).
- **Refactoring**: Avoid modifying unrelated code unless fixing a bug.
- **Modularity**: Extend existing classes (e.g., `AdvancedScanner`) rather than duplicating logic.

### 7.2 Security
- **No Hardcoded Secrets**: Use `QuantumEncryptor` or environment variables.
- **Minimal Permissions**: Ensure new code respects 0o600/0o700 permissions.
- **Safe Dependencies**: Avoid adding new dependencies unless critical; pin versions in `requirements.txt`.

### 7.3 Testing
- **Edge Cases**:
  - Test invalid inputs (e.g., malformed URLs, empty configs).
  - Test failure scenarios (e.g., network timeouts, Tor unavailable).
- **Mocking**: Mock external services (e.g., Web3 provider, PCAP files) to avoid live dependencies.
- **Regression**: Ensure existing tests pass after changes.

### 7.4 Documentation
- **Update Docstrings**: Reflect any changes in method signatures or behavior.
- **CLI Options**: Document new `--flags` in `DuskProbe_Documentation.md`.
- **Examples**: Add usage examples for new features or plugins.

## 8. Review Checklist

Before submitting a PR, verify:
- [ ] Code follows PEP 8 and passes `pylint` (score >8/10).
- [ ] Type hints are included for all new functions/methods.
- [ ] Docstrings are updated in Google style.
- [ ] Tests cover new code (>80% coverage).
- [ ] Security checks pass (no injection risks, proper permissions).
- [ ] Plugins include HMAC signatures and tests.
- [ ] Documentation is updated (README, docstrings, external docs).
- [ ] Commits are atomic with clear messages linking to issues.
- [ ] PR description includes issue reference, changes, and test results.

## 9. Contact

For questions or clarification:
- **Issue Tracker**: Post in the repository’s issue section.
- **Email**: `dev@x.ai` (for sensitive or private inquiries).
- **Response Time**: Expect replies within 3-5 business days.

## 10. Code of Conduct
- Follow the project’s Code of Conduct (if provided) or general open-source principles.
- Be respectful, collaborative, and open to feedback.
- Avoid submitting malicious code or violating ethical scanning guidelines.

**Thank you for contributing to DuskProbe! Your efforts help improve a powerful, secure vulnerability scanner.**


## Project Documentation

<div style="display: flex; gap: 10px; margin: 15px 0; align-items: center; flex-wrap: wrap;">

[![License](https://img.shields.io/badge/License-See_FILE-007EC7?style=for-the-badge&logo=creativecommons)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Policy_%7C_Reporting-FF6D00?style=for-the-badge&logo=owasp)](SECURITY.md)
[![Contributing](https://img.shields.io/badge/Contributing-Guidelines-2E8B57?style=for-the-badge&logo=git)](CONTRIBUTING.md)
[![Code of Conduct](https://img.shields.io/badge/Code_of_Conduct-Community_Standards-FF0000?style=for-the-badge&logo=opensourceinitiative)](CODE_OF_CONDUCT.md)

</div>

## Contact Information



  
[![Email](https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:labib.45x@gmail.com)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/la-b-ib)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/la-b-ib/)
[![Portfolio](https://img.shields.io/badge/Website-0A5C78?style=for-the-badge&logo=internet-explorer&logoColor=white)](https://la-b-ib.github.io/)
[![X](https://img.shields.io/badge/X-000000?style=for-the-badge&logo=twitter&logoColor=white)](https://x.com/la_b_ib_)






---

