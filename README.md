#  sql-ai-security-tool

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A final project from **INSA** combining three modules built by three groups:

- **Group 1 — SQL Injection Scanner & Injector**  
- **Group 2 — API Endpoint Finder & Fuzzer**  
- **Group 3 — AI Security Advisor**

---

## Description
This repository is a modular offensive security framework that automatically:
1. Crawls applications to discover endpoints and parameters.  
2. Scans for SQL injection vulnerabilities and can perform controlled exploitation.  
3. Fuzzes APIs (auth detection, rate-limit checks, hidden parameters).  
4. Uses a local AI advisor to explain findings and recommend mitigations.

Supports CLI and a Web UI for visualization. Outputs reports in **JSON**, **HTML**, and **PDF** formats.

---

## Features
- Automated endpoint crawling and parameter extraction.  
- Smart SQLi detection (error-based, boolean-based, time-based).  
- DBMS fingerprinting and safe exploitation (list DBs/tables, sample rows).  
- API discovery, auth detection (JWT/OAuth), and parameter fuzzing.  
- AI advisor explains vulnerabilities and suggests fixes.  
- CLI interactive menu and Web dashboard (starter).  
- Exportable reports (JSON/HTML/PDF).

---

## Project Structure

sql-ai-security-tool/
│── README.md
│── requirements.txt
│── setup.py
│── config.yaml
│── main.py
│
├── core_sql/ # SQLi scanner & injector (Group 1)
│ ├── scanner.py
│ ├── injector.py
│ ├── payloads.py
│ ├── detector.py
│ ├── fingerprint.py
│ └── report.py
│
├── core_api/ # API endpoint finder (Group 2)
│ ├── crawler.py
│ ├── parser.py
│ ├── fuzzer.py
│ ├── auth.py
│ └── report.py
│
├── core_ai/ # AI advisor (Group 3)
│ ├── chatbot.py
│ ├── trainer.py
│ ├── inference.py
│ └── dataset/
│ ├── sqli_samples.json
│ ├── api_vulns.json
│ └── owasp_top10.json
│
├── utils/ # Shared utilities
│ ├── logger.py
│ ├── http_client.py
│ ├── config_loader.py
│ ├── output.py
│ └── exceptions.py
│
├── interface/ # CLI & Web UI
│ ├── cli.py
│ └── webui/
│ ├── app.py
│ ├── static/
│ └── templates/
│
└── tests/ # Unit & integration tests
├── test_sql.py
├── test_api.py
├── test_ai.py
└── test_integration.py