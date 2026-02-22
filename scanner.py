import requests
import sys
import re
from colorama import Fore, Style, init

init(autoreset=True)

def extract_frame_ancestors(csp_value):
    match = re.search(r"frame-ancestors\s+([^;]+)", csp_value, re.IGNORECASE)
    return match.group(1).strip() if match else None

def check_clickjacking(target_url):
    try:
        response = requests.get(target_url, timeout=10)
        headers = response.headers

        xfo_header = headers.get("X-Frame-Options")
        csp_header = headers.get("Content-Security-Policy")

        xfo_value = (xfo_header or "").upper()
        frame_ancestors_value = extract_frame_ancestors(csp_header or "")

        xfo_protected = xfo_value in ("DENY", "SAMEORIGIN")
        csp_protected = frame_ancestors_value is not None and "*" not in frame_ancestors_value.split()

        print(f"\n{Fore.CYAN}Checking: {target_url}{Style.RESET_ALL}")
        print(Fore.CYAN + "="*50 + Style.RESET_ALL)

        if xfo_header:
            if xfo_protected:
                print(Fore.GREEN + 
                      "X-Frame-Options properly protects against clickjacking." + 
                      Style.RESET_ALL)
            else:
                print(Fore.RED + 
                      "X-Frame-Options is present but weak. "
                      "Unsupported values are ignored by browsers, effectively disabling protection." + 
                      Style.RESET_ALL)
        else:
            print(Fore.RED + 
                  "X-Frame-Options Header: MISSING. "
                  "This allows attackers to embed the page inside a malicious iframe." + 
                  Style.RESET_ALL)

        if csp_header:
            if frame_ancestors_value:
                print(f"frame-ancestors Directive: {frame_ancestors_value}")
                if csp_protected:
                    print(Fore.GREEN + 
                          "CSP frame-ancestors properly restricts framing." + 
                          Style.RESET_ALL)
                else:
                    print(Fore.RED + 
                          "CSP frame-ancestors is permissive. "
                          "A wildcard (*) permits framing by any origin." + 
                          Style.RESET_ALL)
            else:
                print(Fore.RED + 
                      "frame-ancestors Directive: MISSING. "
                      "CSP does not restrict which sites may frame this page." + 
                      Style.RESET_ALL)
        else:
            print(Fore.RED + 
                  "Content-Security-Policy Header: MISSING. "
                  "No framing restrictions are enforced via CSP." + 
                  Style.RESET_ALL)

        if xfo_protected and csp_protected:
            print(Fore.GREEN + "\nResult: PROTECTED FROM CLICKJACKING: X-Frame-Options and CSP frame-ancestors are sufficient." + Style.RESET_ALL)
        elif xfo_protected:
            print(Fore.GREEN + "\nResult: PROTECTED FROM CLICKJACKING: X-Frame-Options is sufficient." + Style.RESET_ALL)
        elif csp_protected:
            print(Fore.GREEN + "\nResult: PROTECTED FROM CLICKJACKING: CSP frame-ancestors is sufficient." + Style.RESET_ALL)
        else:
            print(Fore.RED + "\nResult: VULNERABLE TO CLICKJACKING: missing or misconfigured X-Frame-Options and CSP frame-ancestors." + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"Error: Could not reach site {target_url}" + Style.RESET_ALL)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <url>")
        sys.exit(1)

    for url in sys.argv[1:]:
        check_clickjacking(url)
