import colorama
from colorama import *
import requests
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import readline
import socket
import sys
import os
import json

colorama.init()

def giantcock():
   if sys.platform == "linux":
    os.system("clear")
   elif sys.platform == "win32":
    os.system("cls")

def cumportscanner(owo, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.5)
        s.connect((owo, port))
        print(f"{Fore.GREEN}   Port {port} is open{Style.RESET_ALL}")
        s.close()
    except:
        print(f"{Fore.RED}   Port {port} is closed or filtered{Style.RESET_ALL}")

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"

def scan_security_headers(url):
    headers = {}
    response = requests.get(url, headers=headers)

    if 'content-security-policy' in response.headers:
        print(f'{Fore.GREEN}   Content-Security-Policy found:', response.headers['content-security-policy'])

    if 'strict-transport-security' in response.headers:
        print(f'{Fore.GREEN}   HTTP Strict Transport Security found:', response.headers['strict-transport-security'])

def find_js_files(url):
    if url.endswith('/'):
        url = url[:-1]
    response = requests.get(url, timeout=10)

    soup = BeautifulSoup(response.content, 'html.parser')

    script_tags = soup.find_all('script')

    js_files = [tag['src'] for tag in script_tags if 'src' in tag.attrs]

    for file in js_files:
        print(f'{Fore.GREEN}   Found: {file}')

def find_links(url):
    if url.endswith('/'):
        url = url[:-1]
    response = requests.get(url)

    soup = BeautifulSoup(response.content, 'html.parser')

    link_tags = soup.find_all('a')

    links = [tag['href'] for tag in link_tags if 'href' in tag.attrs]

    for link in links:
        print(f'{Fore.GREEN}   Found link: {link}')
#most scuffed thing ive made lmao its so bad
def find_sensitive_info(url):
    response = requests.get(url)
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    phone_regex = r'\b(?:\d{3}[-.\s]?\d{3}[-.\s]?\d{4}|\(\d{3}\)\s*\d{3}[-.\s]?\d{4})\b'
    tel_regex = r'tel:\+?\d{1,}'
    ssn_regex = r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b'
    cc_regex = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b'
    password_regex = r'\b(?:password|passwd|pwd)[:=]?(\S+)\b'
    emails = re.findall(email_regex, response.text)
    phones = re.findall(phone_regex, response.text)
    tels = re.findall(tel_regex, response.text)
    ssns = re.findall(ssn_regex, response.text)
    ccs = re.findall(cc_regex, response.text)
    passwords = re.findall(password_regex, response.text)

    if emails:
        for email in emails:
            print(f'{Fore.GREEN}   Emails found: {email}')

    if phones:
        for phone in phones:
            print(f'{Fore.GREEN}   Phone numbers found: {phone}')

    if tels:
        for tel in tels:
            print(f'{Fore.GREEN}   Tel links found: {tel}')

    if ssns:
        for ssn in ssns:
            print(f'{Fore.GREEN}   SSNs found: {ssn}')

    if ccs:
        for cc in ccs:
            print(f'{Fore.GREEN}   Credit card numbers found: {cc}')

    if passwords:
        for password in passwords:
            print(f'{Fore.GREEN}   Passwords found: {password}')

def find_stylesheets(url):
    if url.endswith('/'):
        url = url[:-1]
    response = requests.get(url)

    soup = BeautifulSoup(response.content, 'html.parser')

    link_tags = soup.find_all('link')

    stylesheets = [tag['href'] for tag in link_tags if 'href' in tag.attrs and tag['href'].endswith('.css')]

    for stylesheet in stylesheets:
        print(f'{Fore.GREEN}   Found stylesheet: {stylesheet}')

def find_metadata(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    meta_tags = soup.find_all('meta')
    metadata = {}
    for tag in meta_tags:
        tag_name = tag.get('name')
        if tag_name:
            tag_content = tag.get('content')
            metadata[tag_name] = tag_content
    if metadata:
        for key, value in metadata.items():
            print(f'{Fore.GREEN}   Metadata found: {key}: {value}')

def find_images(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    img_tags = soup.find_all('img')
    image_urls = [img['src'] for img in img_tags]
    for url in image_urls:
        print(f'{Fore.GREEN}   Found image: {url}')

def find_files(url):
    files = ['sitemap.xml', 'robots.txt', 'en/wp-json/', 'wp-json/', 'wp-login.php', 'login.php', 'admin/login.php', 'admin.php', 'xmlrpc.php', 'wp-cron.php', 'panel', 'webadmin', 'modir', 'manage', 'administration', 'joomla/administrator', 'joomla/admin', 'CM/', 'mu-plugins/', 'wp-content/uploads', 'wp-mail.php', 'admin', 'admin_area', 'administrator', '.env', 'phpmyadmin', 'browserconfig.xml', 'crossdomain.xml', 'web.config', 'apple-touch-icon.png', 'apple-touch-icon-precomposed.png', 'security.txt', 'humans.txt', 'license.txt', 'wp-links-opml.php', '.htaccess', '.git', 'wp-config.php', 'config.php', 'phpinfo.php']
    if url.endswith('/'):
        url = url[:-1]

    for file in files:
        try:
            res = requests.get(f'{url}/{file}', timeout=10)
            if res.status_code == 200:
                if 'Page not found' in res.text or 'does not exist' in res.text:
                    continue
                print(f'{Fore.GREEN}   Found: {url}/{file}')
            elif res.status_code == 401:
                print(f'{Fore.GREEN}   Found (requires authentication): {url}/{file}')
        except requests.exceptions.RequestException as e:
            continue

def wafDetector(url, params, headers, GET, delay, timeout):
    with open(sys.path[0] + '/waf/waf.json', 'r') as file:
        wafSignatures = json.load(file)
    
    noise = '<script>alert("XSS")</script>'
    params['xss'] = noise
    
    response = requests.get(url, params=params, headers=headers, timeout=timeout)
    
    page = response.text
    code = str(response.status_code)
    headers = str(response.headers)
    print('   Response code: {}'.format(code))
    if int(code) >= 400:
        bestMatch = [0, None]
        for wafName, wafSignature in wafSignatures.items():
            score = 0
            pageSign = wafSignature['page']
            codeSign = wafSignature['code']
            headersSign = wafSignature['headers']
            
            if pageSign:
                if re.search(pageSign, page, re.I):
                    score += 1
            if codeSign:
                if re.search(codeSign, code, re.I):
                    score += 0.5
            if headersSign:
                if re.search(headersSign, headers, re.I):
                    score += 1
            
            if score > bestMatch[0]:
                del bestMatch[:]
                bestMatch.extend([score, wafName])
        
        if bestMatch[0] != 0:
            return bestMatch[1]
        else:
            return None
    else:
        return None

def cumcrawler(url):
    print(f'{Fore.MAGENTA}   Sanning for WAF')
    params = {}
    headers = {'User-Agent': USER_AGENT}
    GET = True
    delay = 0
    timeout = 10
    wafcum = wafDetector(url, params, headers, GET, delay, timeout)
    cummers = ''
    if wafcum is not None:
        print(f"{Fore.RED}   WAF detected:", wafcum)
        cummers = input(f"{Fore.MAGENTA}   Do you want to continue scanning? (Y/N): {Style.RESET_ALL}")
    if cummers.lower() == 'n':
        sys.exit()
    print(f'{Fore.MAGENTA}   Searching for security headers{Style.RESET_ALL}')
    scan_security_headers(url)
    print(f'{Fore.MAGENTA}   Searching for .js files{Style.RESET_ALL}')
    find_js_files(url)
    print(f'{Fore.MAGENTA}   Searching for metadata{Style.RESET_ALL}')
    find_metadata(url)
    print(f'{Fore.MAGENTA}   Searching for files{Style.RESET_ALL}')
    find_files(url)
    print(f'{Fore.MAGENTA}   Searching for links{Style.RESET_ALL}')
    find_links(url)
    print(f'{Fore.MAGENTA}   Searching for stylesheets{Style.RESET_ALL}')
    find_stylesheets(url)
    print(f'{Fore.MAGENTA}   Searching for images{Style.RESET_ALL}')
    find_images(url)
    print(f'{Fore.MAGENTA}   Searching for sensitive info{Style.RESET_ALL}')
    find_sensitive_info(url)
    print(f'{Fore.MAGENTA}   Scan complete{Style.RESET_ALL}')

def menu():
    print(f"{Fore.BLUE}   Made By: Lotus\n\n   1. Port Scanner\n   2. Site Crawler\n   3. Exit\n")

    choice = input(f"   Enter your choice: {Style.RESET_ALL}")

    if choice == "1":
      owo = input("   Enter the host to scan: ")
      penis = input("   Enter the ports to scan (separated by commas): ")
      shit = [int(port) for port in penis.split(",")]
      for port in shit:
        cumportscanner(owo, port)
    elif choice == "2":
        easports = input("   Enter the URL to scan: ")
        cumcrawler(easports)
    elif choice == "3":
        print("   Exiting!")
        sys.exit()
    else:
        giantcock()
        menu()

giantcock()
menu()
