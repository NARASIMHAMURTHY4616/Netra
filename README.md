# 🔱 Netra Security


<img src="https://raw.githubusercontent.com/NARASIMHAMURTHY4616/Netra-security/main/Gemini_Generated_Image_6gr6k6gr6k6gr6k6.png" alt="Netra Security">

**Netra Security** is a lightweight Static Application Security Testing (SAST) platform built with Python and Flask. Inspired by the concept of the "third eye" (Netra), the project helps developers identify common security vulnerabilities in Python source code through rule-based and AST-based analysis.

---

## 🚀 Features

### 🔍 Static Code Analysis
- Rule-based vulnerability detection
- AST (Abstract Syntax Tree) analysis
- Secure coding checks
- Automated security findings generation

### 🛡️ Vulnerability Detection

Currently detects:


| ID | Vulnerability | Severity |
|----|--------------|-----------|
| NETRA-001 | Command Injection (`os.system`) | CRITICAL |
| NETRA-002 | Code Injection (`eval`) | CRITICAL |
| NETRA-003 | Hardcoded Password | HIGH |
| NETRA-004 | Hardcoded API Key | HIGH |
| NETRA-005 | Arbitrary Code Execution (`exec`) | CRITICAL |
| NETRA-006 | Insecure Deserialization (`pickle.loads`) | HIGH |
| NETRA-007 | Dangerous Subprocess Usage (`shell=True`) | HIGH |

---


## 🧠 Detection Techniques


### Rule-Based Analysis
Detects insecure patterns using:
- String matching
- Regular expressions
- Security rules

### AST-Based Analysis
Parses Python source code into an Abstract Syntax Tree and identifies:
- Dangerous function calls
- Insecure code execution
- Command injection patterns
- High-risk operations

---

## 📂 Project Structure

```text
Netra-security/

├── app.py
├── scan_engine.py
├── uploads/
├── templates/
├── static/
├── database/
├── requirements.txt
└── README.md
```

---

## 📋 Sample Report

```text
=== NETRA SECURITY REPORT ===

Total Findings: 5

[CRITICAL]
Issue    : Command Injection
Line     : 13
Code     : os.system(user)

[CRITICAL]
Issue    : Code Injection
Line     : 15
Code     : eval(user)

[HIGH]
Issue    : Hardcoded Password
Line     : 5
Code     : PASSWORD = "admin123"
```

---

## ⚙️ Installation

### Clone the Repository

```bash
git clone https://github.com/NARASIMHAMURTHY4616/Netra-security.git
cd Netra-security
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run the Application

```bash
python app.py
```

Open your browser:

```text
http://127.0.0.1:5000
```

---

## 🎯 Project Goals

- Learn secure coding practices
- Understand Static Application Security Testing (SAST)
- Explore Python AST analysis
- Detect common software vulnerabilities
- Build practical AppSec skills

---

## 🛣️ Roadmap

### Version 1
- Rule-based scanning
- AST-based scanning
- Findings dashboard
- File upload scanning
- JSON export
- CSV export

### Future Versions
- OWASP Top 10 coverage
- Multi-file project scanning
- Scan history tracking
- PDF reports
- Risk scoring
- Custom rule engine
- CI/CD integration
- GitHub repository scanning

---

## 📚 Technologies Used

- Python
- Flask
- SQLite
- HTML5
- CSS3
- JavaScript
- AST Module
- Regular Expressions

---

## ⚠️ Disclaimer

This project is intended for educational and defensive security purposes only. Users are responsible for ensuring compliance with applicable laws and organizational policies.

---

## 👨‍💻 Author

**Narasimhamurthy Balla**

Cybersecurity Student | Python Developer | Aspiring Application Security Engineer

---

### 🔱 See vulnerabilities before attackers do.


#### contributions are hartly welcome
