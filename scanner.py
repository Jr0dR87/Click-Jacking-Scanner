import requests
import sys
import re
from colorama import Fore, Style, init

init()

def extract_frame_ancestors(csp_value):
    match = re.search(r"frame-ancestors\s+([^;]+)", csp_value, re.IGNORECASE)
    return match.group(1).strip() if match else None

def validate_clickjacking(target_url):
    try:
        http_response = requests.get(target_url, timeout=10)
        response_headers = http_response.headers

        x_frame_options_header = response_headers.get("X-Frame-Options")
        content_security_policy_header = response_headers.get("Content-Security-Policy")

        x_frame_options_value = (x_frame_options_header or "").upper()
        frame_ancestors_value = extract_frame_ancestors(content_security_policy_header or "")

        valid_xfo_protection = x_frame_options_value in ("DENY", "SAMEORIGIN")

        valid_csp_protection = (
            frame_ancestors_value is not None and
            "*" not in frame_ancestors_value.split()
        )

        print(f"\n{Fore.CYAN}Checking: {target_url}{Style.RESET_ALL}")
        print(Fore.CYAN + "=" * 50 + Style.RESET_ALL)

        if x_frame_options_header:
            print(Fore.GREEN + "X-Frame-Options Header Present" + Style.RESET_ALL)
            print(f"X-Frame-Options Value: {x_frame_options_header}")

            if valid_xfo_protection:
                print(Fore.GREEN + "X-Frame-Options Protection: Valid" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "X-Frame-Options Protection: Invalid / Weak" + Style.RESET_ALL)
        else:
            print(Fore.RED + "X-Frame-Options Header: MISSING" + Style.RESET_ALL)

        if content_security_policy_header:
            print(Fore.GREEN + "\nContent-Security-Policy Header Present" + Style.RESET_ALL)

            if frame_ancestors_value:
                print("frame-ancestors Directive Found")
                print(f"frame-ancestors Value: {frame_ancestors_value}")

                if valid_csp_protection:
                    print(Fore.GREEN + "CSP Protection: Valid" + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + "CSP Protection: Weak / Permissive" + Style.RESET_ALL)
            else:
                print(Fore.RED + "frame-ancestors Directive: MISSING" + Style.RESET_ALL)
        else:
            print(Fore.RED + "\nContent-Security-Policy Header: MISSING" + Style.RESET_ALL)

        print(Fore.CYAN + "\nX-Frame-Options Results:" + Style.RESET_ALL)
        if x_frame_options_header:
            if valid_xfo_protection:
                print(Fore.GREEN + "Valid X-Frame-Options protection detected" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "X-Frame-Options header present but not protective" + Style.RESET_ALL)
        else:
            print(Fore.RED + "X-Frame-Options header missing" + Style.RESET_ALL)

        print(Fore.CYAN + "\nContent-Security-Policy Results:" + Style.RESET_ALL)
        if content_security_policy_header:
            if valid_csp_protection:
                print(Fore.GREEN + "Valid frame-ancestors protection detected" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "Content-Security-Policy present but not protective" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Content-Security-Policy header missing" + Style.RESET_ALL)

    except Exception as error_message:
        print(Fore.RED + f"Error: {target_url} -> {error_message}" + Style.RESET_ALL)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <url>")
        sys.exit(1)

    for provided_url in sys.argv[1:]:
        validate_clickjacking(provided_url)
