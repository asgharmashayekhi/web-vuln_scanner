# Web Vulnerability Scanner

A modular, Python-based web vulnerability scanner designed to detect common security vulnerabilities such as SQL Injection (SQLi), Cross-Site Scripting (XSS), and Cross-Site Request Forgery (CSRF). This tool generates a detailed HTML report of findings and is built with extensibility in mind.

## ScreenShot

(https://github.com/asgharmashayekhi/web-vuln_scanner/blob/main/ScreenShot/tsting_app.png?raw=true)
(https://github.com/asgharmashayekhi/web-vuln_scanner/blob/main/ScreenShot/Report_1.png?raw=true)
(https://github.com/asgharmashayekhi/web-vuln_scanner/blob/main/ScreenShot/Report_2.png?raw=true)
(https://github.com/asgharmashayekhi/web-vuln_scanner/blob/main/ScreenShot/Report_3.png?raw=true)
(https://github.com/asgharmashayekhi/web-vuln_scanner/blob/main/ScreenShot/Report_4.png?raw=true)

## Features

- Detects multiple web vulnerabilities:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
- Supports anonymous scanning via proxy or Tor integration
- Generates comprehensive HTML reports
- Modular and extensible design for adding new scan types
- Includes User-Agent rotation for stealth scanning
- Multi-threaded scanning for improved performance


## Prerequisites

- Python 3.6 or higher
- Tor (optional, for anonymous scanning via proxy)
- Git (for cloning the repository)


## Installation

1. Clone this repository:
```
git clone https://github.com/yourusername/web-vuln-scanner.git
cd web_vuln_scanner
```

2. Install the required dependencies:
```
pip install -r requirements.txt
```

3. (Optional) For anonymous scanning with Tor:
- Install Tor on your system (e.g., sudo apt install tor on Ubuntu).
- Start the Tor service: tor

## Usage

### Basic Usage

Scan a target URL with default settings:

```
python scanner.py --url https://example.com
```

### Advanced Options

Customize your scan with additional arguments:

```
python scanner.py --url https://example.com --proxy socks5://127.0.0.1:9050 --user-agent-rotate --output report.html --verbose
```



#### Command Line Arguments

- `--url`: Target URL to scan (required)
- `--output`: Output file for HTML report (default: vuln_report.html)
- `--proxy`: Proxy server to use (e.g., socks5://127.0.0.1:9050 for Tor)
- `--user-agent-rotate`: Enable User-Agent rotation
- `--scan-type`: Specify scan types (options: sqli, xss, csrf, all) (default: all)
- `--threads`: Number of threads to use for scanning (default: 5)
- `--timeout`: Request timeout in seconds (default: 10)
- `--verbose`: Enable verbose output
- `--delay`: Delay between requests in seconds (default: 1)

## Example

Run a full scan with verbose output:

```
python scanner.py --url http://testphp.vulnweb.com --scan-type all --verbose
```

## Extending the Scanner

To add a new vulnerability scanner:

1. Navigate to the tests/ directory
2. Create a new class inheriting from BaseScanner.
3. Implement the scan method with your logic.
4. Register your scanner in `scanner.py`

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch (git checkout -b feature-branch).
3. Commit your changes (git commit -am 'Add some feature').
4. Push to the branch (git push origin feature-branch).
5. Create a new Pull Request.


## License

This project is licensed under the MIT License (LICENSE).



## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Do not use it on websites or systems without explicit permission from the owner. The authors are not liable for any misuse or damage caused by this tool.

---
📌 Developer: Asghar MAshayekhi  
📅 Project Date: April 2025  
📫 Contact: dallvllon@gmail.com
GitHub: asgharmashayekhi
