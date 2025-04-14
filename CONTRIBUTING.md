
# Contributing to DuskProbe

We’re excited to have you contribute to **DuskProbe**, a professional-grade, open-source web vulnerability scanner. Whether you're fixing a bug, improving documentation, building new features, or suggesting ideas, your help is appreciated!

This document outlines the process for contributing to the project in a structured and consistent way.

---

##  Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Setting Up the Development Environment](#setting-up-the-development-environment)
- [Coding Guidelines](#coding-guidelines)
- [Making a Contribution](#making-a-contribution)
- [Pull Request Process](#pull-request-process)
- [Writing and Running Tests](#writing-and-running-tests)
- [Documentation Updates](#documentation-updates)
- [Reporting Issues](#reporting-issues)
- [Contact](#contact)

---

##  Code of Conduct

We are committed to fostering a welcoming, inclusive, and respectful environment for everyone. Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

---

##  How to Contribute

There are many ways to contribute:

-  Suggest a feature
-  Report a bug
-  Fix a bug
-  Improve performance or code readability
-  Write unit/integration tests
-  Improve documentation
-  Build plugins
-  Translate text/localize content

---

##  Setting Up the Development Environment

1. **Clone the Repository**

   ```bash
   git clone https://github.com/la-b-ib/DuskProbe.git
   cd DuskProbe
   ```

2. **Create a Virtual Environment**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Linux/macOS
   venv\Scripts\activate     # On Windows
   ```

3. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Verify Setup**

   Run a quick check to ensure the scanner is working:

   ```bash
   python duskprobe.py -h
   ```

---

##  Coding Guidelines

- Follow **PEP8** standards.
- Use descriptive commit messages (e.g., `fix: handle empty URLs in scanner`).
- Keep your changes **modular** and **testable**.
- Comment your code where necessary to improve clarity.
- Avoid hardcoding sensitive or environment-specific values.

---

##  Making a Contribution

1. **Fork the Repository**

   Navigate to [DuskProbe on GitHub](https://github.com/la-b-ib/DuskProbe) and click `Fork`.

2. **Create a Feature Branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**

   - Add your new code.
   - Add/update test cases.
   - Add new configuration if needed (e.g., `payloads.json`).
   - Update relevant documentation if applicable.

4. **Commit Your Changes**

   ```bash
   git add .
   git commit -m "feat: add [brief feature description]"
   ```

5. **Push to Your Fork**

   ```bash
   git push origin feature/your-feature-name
   ```

---

##  Pull Request Process

1. Open a pull request (PR) against the `main` branch.
2. Follow the PR template:
   - Describe your changes in detail.
   - Mention the related issue if applicable.
   - Provide before/after results if it affects CLI, scans, or reports.

3. The PR will be reviewed by a maintainer:
   - You may be asked to make changes.
   - Once approved, it will be merged into the main branch.

 Tip: Ensure your code passes all tests before submitting a PR.

---

##  Writing and Running Tests

- All test files are located in the `/tests` directory.
- Use `unittest` or `pytest` to write and run tests.

```bash
pytest tests/
```

- Create a test for every new module or function.
- Mock HTTP responses using `requests-mock` or similar libraries.

---

##  Documentation Updates

- Documentation lives in the `docs/` directory and the main `README.md`.
- Keep documentation up-to-date with code.
- Use Markdown syntax for formatting.
- For new features, document usage examples and configuration changes.

---

##  Reporting Issues

If you find a bug or security issue:

1. Open an [Issue](https://github.com/la-b-ib/DuskProbe/issues) on GitHub.
2. Provide:
   - A clear description of the problem.
   - Steps to reproduce the issue.
   - Environment (OS, Python version).
   - Screenshots or logs, if available.

For security vulnerabilities, please contact us directly via email.

---

##  Contact

- **Project Maintainer:** [Labib Bin Shahed](https://github.com/la-b-ib)
- **Email:** [labib-x@protonmail.com](mailto:labib-x@protonmail.com)
- **GitHub Repo:** [https://github.com/la-b-ib/DuskProbe](https://github.com/la-b-ib/DuskProbe)
- **Website:** [https://la-b-ib.github.io](https://la-b-ib.github.io)

---

##  Thank You

Thank you for considering contributing to DuskProbe! Every bit of effort helps improve this powerful security tool. Together, we can build a stronger, more secure web.
