#!/usr/bin/env python3
"""
SQL-AI Security Tool - CLI Menu
"""

import sys
from utils import logger, output
from core_api import crawler
from core_sql import scanner, injector
from core_ai import inference


def main():
    while True:
        print("\n=== SQL-AI Security Tool ===")
        print("1. Crawl API endpoints")
        print("2. Scan for SQL Injection")
        print("3. Exploit SQL Injection")
        print("4. Ask AI Advisor about a vulnerability")
        print("5. Full Scan + Report")
        print("0. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            url = input("Enter target URL: ").strip()
            endpoints = crawler.crawl(url)
            print("\n[Discovered Endpoints]")
            for ep in endpoints:
                print(ep)

        elif choice == "2":
            url = input("Enter target URL: ").strip()
            param = input("Enter parameter (e.g., id): ").strip()
            result = scanner.scan(url, [param])
            print("\n[Scan Result]")
            print(result)

        elif choice == "3":
            url = input("Enter vulnerable URL: ").strip()
            param = input("Enter vulnerable parameter: ").strip()
            result = injector.exploit(url, param)
            print("\n[Exploitation Result]")
            print(result)

        elif choice == "4":
            url = input("Enter URL: ").strip()
            param = input("Enter parameter: ").strip()
            vuln = {"url": url, "param": param, "vulnerable": True}
            explanation = inference.explain(vuln)
            print("\n[AI Explanation]")
            print(explanation)

        elif choice == "5":
            url = input("Enter target URL: ").strip()
            endpoints = crawler.crawl(url)
            scan_results = [scanner.scan(ep["url"], ep.get("params", [])) for ep in endpoints]
            exploitation_results = [
                injector.exploit(v["url"], v["param"]) for v in scan_results if v.get("vulnerable")
            ]
            explanations = [inference.explain(v) for v in scan_results]

            final_report = {
                "target": url,
                "endpoints": endpoints,
                "vulnerabilities": scan_results,
                "exploitation": exploitation_results,
                "ai_explanations": explanations
            }

            output.save_json(final_report, "report.json")
            logger.log_success("Full report saved to report.json")

        elif choice == "0":
            print("Goodbye 👋")
            sys.exit(0)

        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()
