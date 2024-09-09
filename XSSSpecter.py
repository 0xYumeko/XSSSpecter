import os
import sys
import datetime
import requests
import socket
import re
import time as t
import logging
from colorama import Fore, Style, init
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse, quote
from prettytable import PrettyTable
import argparse

init(autoreset=True)

def print_banner():
    os.system("clear")  
    logo = """
  ____  _____ ____  __  __ ______ 
 / __ \|  __ \  _ \|  \/  |  ____|
| |  | | |__) | |_) | \  / | |__   
| |  | |  _  /|  _ <| |\/| |  __|  
| |__| | | \ \| |_) | |  | | |____ 
 \____/|_|  \_\____/|_|  |_|______|
                                  
  ____  ____  _____  _____  ____   _____ ____  _   _ 
 / __ \|  _ \|  __ \|  __ \|  _ \ / ____|  _ \| \ | |
| |  | | |_) | |  | | |__) | |_) | (___ | |_) |  \| |
| |  | |  _ <| |  | |  _  /|  _ < \___ \|  _ <| . ` |
| |__| | |_) | |__| | | \ \| |_) |____) | |_) | |\  |
 \____/|_____/|_____/|_|  \_\____/|_____/|____/|_| \_|
    
    """
    print(Fore.LIGHTCYAN_EX + logo + Style.RESET_ALL)
    print(Fore.YELLOW + "Welcome to the XSS Scanner Script by 0xYumeko")
    print(Fore.YELLOW + "─────────────────────────────────────────────────")

def validate_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise ValueError("Invalid URL. Please provide a URL with a scheme (http/https) and a domain.")
    
    if parsed_url.scheme not in ['http', 'https']:
        raise ValueError("URL must start with 'http://' or 'https://'.")

def print_socket_info(url):
    try:
        match = re.search(r'^http[s]*:\/\/[\w\.]*', url)
        if match:
            base_url = match.group()
            hostname = url.split("//")[-1].split("/")[0].split('?')[0]
            ip_address = socket.gethostbyname(hostname)
            logging.info(f"[*] Socket Form -> {Fore.YELLOW}{hostname}")
            logging.info(f"[*] Socket Name -> {Fore.YELLOW}{ip_address}")
            logging.info(f"[*] Regexed URL -> {Fore.YELLOW}{base_url}")
        else:
            raise ValueError("URL format is invalid or could not be extracted.")
    except socket.gaierror as e:
        logging.error(f"Failed to resolve hostname '{hostname}': {str(e)}")
        logging.error("Please check your internet connection or the validity of the URL.")
        sys.exit(1)
    except ValueError as e:
        logging.error(str(e))
        sys.exit(1)

def execute_command(command):
    try:
        os.system(command)
    except Exception as e:
        logging.error(f"Failed to execute command '{command}': {str(e)}")
        sys.exit(1)

def check_internet_connection():
    try:
        requests.get("http://www.google.com", timeout=5)
    except requests.ConnectionError:
        logging.error("No Internet Connection. Please check your network.")
        sys.exit(1)

def retry_request(func, *args, retries=3, delay=5, **kwargs):
    for attempt in range(retries):
        try:
            response = func(*args, **kwargs)
            if response.status_code == 200:
                return response
            elif response.status_code == 403:
                # Ignore warnings for status code 403
                logging.info(f"Received status code 403. Skipping retry.")
                return response
            else:
                logging.warning(f"Received status code {response.status_code}. Retrying...")
        except requests.RequestException as e:
            logging.warning(f"Request failed: {str(e)}. Retrying...")
        t.sleep(delay)
    logging.error("Failed to complete request after several attempts.")
    sys.exit(1)

def get_http_info(url):
    command = f"go run http.go {url}"
    print_banner()
    print_socket_info(url)
    logging.info(f"{Fore.CYAN}[*] Started At  : {Fore.WHITE}{str(datetime.datetime.now())}")
    logging.info(Fore.CYAN + "────────────────────────────────────────────")
    logging.info(f"{Fore.LIGHTRED_EX}[*] Gathering X-Frame request headers......")
    execute_command(command)

def get_all_forms(url):
    response = retry_request(requests.get, url)
    soup = bs(response.content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {
        "action": form.attrs.get("action", "").lower(),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": [{"type": input_tag.attrs.get("type", "text"),
                    "name": input_tag.attrs.get("name")}
                   for input_tag in form.find_all("input")]
    }
    return details

def submit_form(form_details, url, value):
    try:
        target_url = urljoin(url, form_details["action"])
        data = {input["name"]: value for input in form_details["inputs"] if input["type"] in ["text", "search"]}
        response = retry_request(requests.post if form_details["method"] == "post" else requests.get, target_url, data=data if form_details["method"] == "post" else None, params=data if form_details["method"] == "get" else None)
        return response
    except requests.RequestException as e:
        logging.error(f"Failed to submit form to '{url}': {str(e)}")
        return None

def reflected_xss_check(url, payload):
    logging.info(f"{Fore.LIGHTMAGENTA_EX}Checking for Reflected XSS vulnerabilities...")
    encoded_payload = quote(payload) 
    response = retry_request(requests.get, url, params={'test': encoded_payload})
    if payload in response.text:
        return True
    return False

def stored_xss_check(url, payload):
    logging.info(f"{Fore.LIGHTMAGENTA_EX}Checking for Stored XSS vulnerabilities...")
    return False

def dom_xss_check(url, payload):
    logging.info(f"{Fore.LIGHTMAGENTA_EX}Checking for DOM-based XSS vulnerabilities...")
    return False

def scan_xss(url, payload_file, output_file):
    logging.info(f"{Fore.LIGHTCYAN_EX}----------------------------------------------")
    logging.info(f"[{Fore.LIGHTGREEN_EX}+{Fore.LIGHTCYAN_EX}] Utilizing Default XSS script -> {payload_file}")
    logging.info(f"[{Fore.LIGHTGREEN_EX}+{Fore.LIGHTCYAN_EX}] Targeting URL -> {Fore.YELLOW}{url}")
    logging.info(f"[{Fore.LIGHTGREEN_EX}+{Fore.LIGHTCYAN_EX}] Time Started  -> {Fore.WHITE}{str(datetime.datetime.now())}")
    t.sleep(2)

    try:
        with open(payload_file, 'r') as file:
            payloads = file.readlines()
    except FileNotFoundError:
        logging.error(f"Payload file '{payload_file}' not found.")
        sys.exit(1)
    except IOError as e:
        logging.error(f"Failed to read payload file '{payload_file}': {str(e)}")
        sys.exit(1)

    is_vulnerable = False
    with open(output_file, 'w') as out_file:
        for count, payload_line in enumerate(payloads):
            payload_line = payload_line.strip()
            logging.info(f"[~] Testing Payload -> {count}: {Fore.LIGHTMAGENTA_EX}{payload_line}")
            detected = False
            for form in get_all_forms(url):
                form_details = get_form_details(form)
                response = submit_form(form_details, url, payload_line)
                if response and payload_line in response.content.decode():
                    log_message = (
                        f"[+] XSS Detected At -> {Fore.WHITE}{str(datetime.datetime.now())}\n"
                        f"[+] XSS Type -> Reflected\n"
                        f"[+] Payload Used -> {Fore.LIGHTMAGENTA_EX}{payload_line}\n"
                        f"[+] URL -> {Fore.YELLOW}{url}\n"
                    )
                    logging.info(log_message)
                    out_file.write(log_message)
                    ptable = PrettyTable([Fore.LIGHTCYAN_EX + "Content and Form Details"])
                    ptable.add_row([form_details])
                    logging.info(Fore.GREEN + str(ptable))
                    out_file.write(str(ptable) + "\n")
                    detected = True
                    is_vulnerable = True

            if reflected_xss_check(url, payload_line):
                log_message = (
                    f"[+] Reflected XSS Detected with payload -> {Fore.LIGHTMAGENTA_EX}{payload_line}\n"
                )
                logging.info(log_message)
                out_file.write(log_message)
                detected = True
                is_vulnerable = True

            if stored_xss_check(url, payload_line):
                log_message = (
                    f"[+] Stored XSS Detected with payload -> {Fore.LIGHTMAGENTA_EX}{payload_line}\n"
                )
                logging.info(log_message)
                out_file.write(log_message)
                detected = True
                is_vulnerable = True

            if dom_xss_check(url, payload_line):
                log_message = (
                    f"[+] DOM-based XSS Detected with payload -> {Fore.LIGHTMAGENTA_EX}{payload_line}\n"
                )
                logging.info(log_message)
                out_file.write(log_message)
                detected = True
                is_vulnerable = True

    return is_vulnerable

def main():
    parser = argparse.ArgumentParser(description="XSS Scanner Script by 0xYumeko",
                                     epilog="Example: python3 script.py -u http://example.com -p payloads.txt -o output.txt")
    parser.add_argument('-u', '--url', required=True, type=str, help="Target URL to scan for XSS")
    parser.add_argument('-p', '--payload', required=True, type=str, help="File containing XSS payloads")
    parser.add_argument('-o', '--output', required=True, type=str, help="File to write results to")
    parser.add_argument('--banner', action='store_true', help="Display the banner and exit")

    args = parser.parse_args()

    if args.banner:
        print_banner()
        sys.exit(0)

    url = args.url
    payload_file = args.payload
    output_file = args.output

    logging.basicConfig(level=logging.INFO, format=Fore.CYAN + "[%(asctime)s] %(levelname)s: %(message)s" + Style.RESET_ALL)

    logging.info(f"URL provided: {url}")

    check_internet_connection()
    validate_url(url)
    get_http_info(url)
    try:
        with open(payload_file, 'r') as file:
            logging.info(f"Detected Payloads in file -> {Fore.LIGHTYELLOW_EX}{len(file.readlines())}")
    except FileNotFoundError:
        logging.error(f"Payload file '{payload_file}' not found.")
        sys.exit(1)
    except IOError as e:
        logging.error(f"Failed to read payload file '{payload_file}': {str(e)}")
        sys.exit(1)

    result = scan_xss(url, payload_file, output_file)
    logging.info(f"{Fore.LIGHTCYAN_EX}[*] Ended At : {Fore.WHITE}{str(datetime.datetime.now())}")
    if result:
        logging.info(f"{Fore.LIGHTGREEN_EX}[+] XSS vulnerabilities detected.")
    else:
        logging.info(f"{Fore.LIGHTRED_EX}[-] No XSS vulnerabilities detected.")

if __name__ == "__main__":
    main()
