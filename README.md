# Clickjacking Scanner

A simple Python script to check whether a web application is vulnerable to **clickjacking**.  
The script analyzes HTTP response headers and reports whether protections are in place via **X-Frame-Options** and **CSP frame-ancestors** directives.

---

## Features

- Checks for `X-Frame-Options` header (`DENY` / `SAMEORIGIN`).  
- Checks for `Content-Security-Policy` header and `frame-ancestors` directive.  
- Provides detailed output explaining why the page is vulnerable or protected.  
- Color-coded output for easy readability.  
- Supports scanning multiple URLs at once.

---

## Requirements

- Python 3.7+  
- [`requests`](https://pypi.org/project/requests/) library  
- [`colorama`](https://pypi.org/project/colorama/) library  

Install dependencies:

```
pip install requests colorama
```

## Usage
python3 scanner.py https://example.com
