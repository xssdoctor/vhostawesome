import requests
from concurrent.futures import ThreadPoolExecutor
import argparse
import logging
from itertools import islice
import os
import json
import urllib3
from time import sleep
from termcolor import colored
from itertools import repeat

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
cwd = os.getcwd()


class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': 'blue',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red',
    }

    def format(self, record):
        log_message = super().format(record)
        return colored(log_message, self.COLORS.get(record.levelname))


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()
for handler in logger.handlers:
    handler.setFormatter(ColoredFormatter(
        '%(asctime)s %(levelname)s %(message)s'))


class Vhosts:
    def __init__(self, domain: str, iplistFile: str, wordlist: str, outputFolder: str, ports: list, workers=50):
        self.ports = ports
        self.chunk_counter = 0
        self.finaldict = {}
        self.filtered_dict = {}
        self.wordlist = wordlist
        self.domain = domain
        self.workers = workers
        self.iplist = []
        if outputFolder.startswith("/"):
            self.outputFolder = outputFolder
        else:
            self.outputFolder = os.path.join(cwd, outputFolder)
        if not os.path.exists(self.outputFolder):
            try:
                os.makedirs(self.outputFolder)
            except Exception as e:
                logging.error(f"Error creating output folder: {e}")
        self.filtereddomainsFile = os.path.join(
            self.outputFolder, "filtereddomains.txt")
        self.allDomainInfoFile = os.path.join(self.outputFolder, "all.txt")
        self.domainList = []
        try:
            with open(wordlist, 'r') as r:
                for word in r.read().splitlines():
                    self.domainList.append(f"{word}.{domain}")
            with open(iplistFile, 'r') as r:
                self.iplist = r.read().splitlines()
        except Exception as e:
            logging.error(f"Error reading file: {e}")
        self.urllist = []

    def domain_generator(self):
        with open(self.wordlist, 'r') as r:
            for word in r:
                yield f"{word.strip()}.{self.domain}"

    def save_to_disk(self, data):
        """Append results directly to a file."""
        with open(self.allDomainInfoFile, 'a') as w:
            json.dump(data, w)
            w.write('\n')

    def _checkPort(self, ip, port):
        url = f"https://{ip}:{port}" if port in [443,
                                                 8443, 4443] else f"http://{ip}:{port}"
        try:
            requests.get(url, timeout=3, verify=False)
            self.urllist.append(url)
            logging.info(f"Found {url} on port {port}")
        except:
            pass

    def checkForOpenPorts(self):
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            for ip in self.iplist:
                for port in self.ports:
                    executor.submit(self._checkPort, ip, port)

    def getSingleUrl(self, url: str, domain: str):
        try:
            headers = {}
            if domain:
                headers["Host"] = domain
            r = requests.get(url, headers=headers, timeout=3, verify=False)
            status_code = r.status_code
            words = len(r.text.split(' '))
            lines = len(r.text.split('\n'))
            chars = len(r.text)
            data = {
                "status_code": status_code,
                "words": words,
                "lines": lines,
                "chars": chars
            }
            if url not in self.finaldict:
                self.finaldict[url] = {}
            # Update the data for the specific domain under the given URL
            self.finaldict[url][domain] = data
        except Exception as e:
            logging.error(f"Error fetching {url}: {e}")
        return domain, data

    def filterUrl(self, url):
        threshold = 5
        if url not in self.finaldict:
            logging.warning(f"URL {url} not found in finaldict. Skipping...")
            return {}

        status_codes = [data["status_code"]
                        for _, data in self.finaldict[url].items()]
        sc_frequent = max(set(status_codes), key=status_codes.count)

        filtered_domains = {}
        for domain, data in self.finaldict[url].items():
            # 1. Filter based on status code deviation
            if data["status_code"] != sc_frequent:
                filtered_domains[domain] = data

        if not filtered_domains:  # If no domains have been filtered yet based on status code
            words_seen = [data["words"]
                          for _, data in self.finaldict[url].items()]
            words_variance = sum(
                [(x - sum(words_seen) / len(words_seen)) ** 2 for x in words_seen]) / len(words_seen)

            if words_variance > threshold:  # If word counts are unreliable
                # 3. Filter based on lines
                lines_seen = [data["lines"]
                              for _, data in self.finaldict[url].items()]
                lines_frequent = max(set(lines_seen), key=lines_seen.count)
                for domain, data in self.finaldict[url].items():
                    if data["lines"] != lines_frequent:
                        filtered_domains[domain] = data
            else:
                # 2. Filter based on words
                words_frequent = max(set(words_seen), key=words_seen.count)
                for domain, data in self.finaldict[url].items():
                    if data["words"] != words_frequent:
                        filtered_domains[domain] = data

        return filtered_domains

    def getAllDomainsFromUrl(self, url: str):
        logging.info(f"Trying {url}")
        url_data = {}  # Dictionary for this specific URL

        domains_gen = self.domain_generator()
        batch_size = 100  # Fetch 100 domains at a time, adjust this value as needed

        while True:
            batch = list(islice(domains_gen, batch_size))
            if not batch:
                break

            with ThreadPoolExecutor(max_workers=self.workers) as executor:
                results = executor.map(
                    self.getSingleUrl, repeat(url, len(batch)), batch)

            # Aggregate results for this URL
            for domain, data in results:
                if domain:  # If there's valid data
                    if domain not in url_data:
                        url_data[domain] = {}
                    url_data[domain] = data

            sleep(1)  # Pause after each batch for rate limiting

        # Save this URL's data to disk
        self.save_to_disk(url_data)

    def getAllIps(self):
        for url in self.urllist:
            self.getAllDomainsFromUrl(url)

    def makeItSo(self):
        logging.info("Checking for open ports")
        self.checkForOpenPorts()
        logging.info("Checking for domains")
        self.getAllIps()


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-d", "--domain", required=True,
                           help="Domain to bruteforce")
    argparser.add_argument("-i", "--iplist", required=True,
                           help="File containing list of IPs")
    argparser.add_argument(
        "-w", "--wordlist", required=True, help="Wordlist to use")
    argparser.add_argument("-t", "--threads", required=False,
                           help="Number of threads to use")
    argparser.add_argument("-o", "--output", required=True, help="Output file")
    argparser.add_argument("-p", "--ports", required=False,
                           help="Ports to scan. if left out, it will scan 80, 8080, 443, 8443, 4443")

    args = argparser.parse_args()
    if args.ports:
        ports = [int(port) for port in args.ports.split(",")]
    else:
        ports = [80, 8080, 443, 8443, 4443]

    if args.threads:
        vhosts = Vhosts(domain=args.domain, iplistFile=args.iplist, wordlist=args.wordlist,
                        outputFolder=args.output, ports=ports, workers=int(args.threads))
    else:
        vhosts = Vhosts(domain=args.domain, iplistFile=args.iplist,
                        wordlist=args.wordlist, ports=ports, outputFolder=args.output)

    vhosts.makeItSo()
