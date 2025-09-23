
---

# 🤝 Contributing to DuskProbe

Welcome, security enthusiast! We're thrilled you're interested in contributing to **DuskProbe v4.5**, a professional-grade web vulnerability scanner. This guide outlines how to contribute effectively, securely, and ethically.

---

## 🧠 Philosophy

DuskProbe is built on three core principles:

- **Security-first**: All code must follow secure development practices.
- **Ethical use**: Contributions must align with responsible disclosure and legal scanning.
- **Technical excellence**: We value clean, modular, and well-documented code.

---

## 🛠️ How to Contribute

### 1. Fork the Repository

```bash
git clone https://github.com/la-b-ib/duskprobe.git
cd duskprobe
git checkout -b feature/YourFeature
```

### 2. Make Your Changes

- Follow [PEP8](https://peps.python.org/pep-0008/) coding standards.
- Write clear, descriptive commit messages.
- Include docstrings and inline comments for complex logic.
- Add unit tests for new features or bug fixes.
- Avoid hardcoded secrets, payloads, or credentials.

### 3. Run Tests

Ensure your changes pass all tests and linting checks:

```bash
pytest
flake8 duskprobe/
```

### 4. Submit a Pull Request

Push your branch and open a pull request:

```bash
git push origin feature/YourFeature
```

Include:

- A clear description of the feature or fix
- Any relevant screenshots, logs, or test output
- Reference to related issues (if applicable)

---

## 🔐 Secure Coding Guidelines

- Validate all user input and sanitize outputs.
- Avoid insecure dependencies or deprecated libraries.
- Use HTTPS for all external requests.
- Implement retry logic and timeouts for network calls.
- Log errors securely without exposing sensitive data.

---

## ⚖️ Ethical Standards

DuskProbe is intended for **authorized security testing only**. Contributions must not:

- Include black-hat payloads or exploit code
- Enable scanning without user consent
- Circumvent ethical disclaimers or prompts

---

## 📦 Feature Suggestions

We welcome ideas for:

- New vulnerability checks (e.g., SSRF, RCE)
- Improved crawling logic
- Report formatting enhancements
- Performance optimizations
- Integration with other tools (e.g., Burp, OWASP ZAP)

Open an issue with the label `enhancement` to start the discussion.

---

## 🧪 Bug Reports

If you find a bug:

1. Search existing issues to avoid duplicates.
2. Open a new issue with:
   - Steps to reproduce
   - Expected vs. actual behavior
   - Environment details (OS, Python version, Colab/local)

Use the label `bug`.

---

## 📜 License

By contributing, you agree that your code will be licensed under the [MIT License](LICENSE).

---

## 🙌 Thank You

Your contributions help make DuskProbe a powerful and ethical tool for the security community. We appreciate your time, skill, and commitment to making the web safer.

---
