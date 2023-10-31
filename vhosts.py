import aiohttp
import argparse
import logging
import os
import json
import asyncio
import urllib3
import numpy as np
from termcolor import colored

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


def logLevel(level="info"):
    logdict = {"debug": logging.DEBUG, "info": logging.INFO,
               "warning": logging.WARNING, "error": logging.ERROR, "critical": logging.CRITICAL}
    logging.basicConfig(level=logdict[level],  # Corrected line
                        format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger()
    for handler in logger.handlers:
        handler.setFormatter(ColoredFormatter(
            '%(asctime)s %(levelname)s %(message)s'))


class Vhosts:
    def __init__(self, domain: str, iplistFile: str, wordlist: str, outputFolder: str, ports: list, workers=50):
        self.ports = ports
        self.finaldict = {}
        self.filtered_dict = {}
        self.domain = domain
        self.workers = workers
        self.iplist = self.iplist_read_file_generator(iplistFile)
        self.domainList = self.domainlist_read_file_generator(
            wordlist, self.domain)
        self.urllist = []
        self.semaphore = asyncio.Semaphore(10)
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

    def domainlist_read_file_generator(self, filename, domain):
        domains = []
        try:
            with open(filename, 'r') as file:
                for line in file:
                    domains.append(f"{line.strip()}.{domain}")
        except Exception as e:
            logging.error(f"Error reading file: {e}")
        return domains

    def iplist_read_file_generator(self, filename):
        ips = []
        try:
            with open(filename, 'r') as file:
                for line in file:
                    ips.append(line.strip())
        except Exception as e:
            logging.error(f"Error reading file: {e}")
        return ips

    async def _checkPort(self, ip, port):
        url = f"https://{ip}:{port}" if port in [443,
                                                 8443, 4443] else f"http://{ip}:{port}"
        async with self.semaphore:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=1, verify_ssl=False):
                        self.urllist.append(url)
                        logging.info(f"Found {url} on port {port}")
            except Exception as e:
                logging.debug(f"Error getting {url}: {e}")

    async def checkForOpenPorts(self):
        tasks = []
        for ip in self.iplist:
            for port in self.ports:
                task = asyncio.create_task(self._checkPort(ip, port))
                tasks.append(task)
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            logging.debug(f"Error checking for open ports: {e}")

    async def getSingleUrl(self, url: str, domain: str):
        try:
            headers = {}
            if domain:
                headers["Host"] = domain
            async with self.semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=1, verify_ssl=False) as response:
                        status_code = response.status
                        text = await response.text()
                        words = len(text.split(' '))
                        lines = len(text.split('\n'))
                        chars = len(text)
                        data = {
                            "status_code": status_code,
                            "words": words,
                            "lines": lines,
                            "chars": chars
                        }
                        if url not in self.finaldict:
                            self.finaldict[url] = {domain: data}
                        else:
                            self.finaldict[url][domain] = data
        except Exception as e:
            logging.debug(f"Error getting {url} with domain {domain}: {e}")

    def filterUrl(self, url):
        threshold = 5
        if url not in self.finaldict:
            logging.debug(f"URL {url} not found in finaldict. Skipping...")
            return {}

        words_seen = [data["words"] for _, data in self.finaldict[url].items()]
        lines_seen = [data["lines"] for _, data in self.finaldict[url].items()]
        status_codes = [data["status_code"]
                        for _, data in self.finaldict[url].items()]

        def variance(numbers):
            mean = sum(numbers) / len(numbers)
            return sum((x - mean) ** 2 for x in numbers) / len(numbers)

        variances = {
            "words": variance(words_seen),
            "lines": variance(lines_seen),
            "status_codes": variance(status_codes),
        }

        logging.debug(f"Variances: {variances}")

        primary_metric = max(variances, key=variances.get)

        logging.debug(f"Primary metric: {primary_metric}")

        filtered_domains = {}
        if primary_metric == "words":
            words_frequent = max(set(words_seen), key=words_seen.count)
            for domain, data in self.finaldict[url].items():
                if data["words"] != words_frequent:
                    filtered_domains[domain] = data
        elif primary_metric == "lines":
            lines_frequent = max(set(lines_seen), key=lines_seen.count)
            for domain, data in self.finaldict[url].items():
                if data["lines"] != lines_frequent:
                    filtered_domains[domain] = data
        elif primary_metric == "status_codes":
            sc_frequent = max(set(status_codes), key=status_codes.count)
            for domain, data in self.finaldict[url].items():
                if data["status_code"] != sc_frequent:
                    filtered_domains[domain] = data

        logging.debug(f"Filtered domains: {filtered_domains}")

        return filtered_domains

    def saveAllDataToFile(self):
        try:
            with open(os.path.join(self.outputFolder, 'alldata.json'), 'w') as w:
                json.dump(self.finaldict, w)
        except Exception as e:
            logging.error(f"Error writing to file: {e}")

    async def getAllDomainsFromUrl(self, url: str):
        # logging.info(f"Trying {url}")
        tasks = []
        for domain in self.domainList:
            task = asyncio.create_task(self.getSingleUrl(url, domain))
            tasks.append(task)
        await asyncio.gather(*tasks)
        filtered_domains = self.filterUrl(url)
        for domain, data in filtered_domains.items():
            status_code = data["status_code"]
            words = data["words"]
            lines = data["lines"]
            chars = data["chars"]
            logging.info(
                f"Found {url} {domain} words: {words} lines: {lines} chars: {chars}")
            with open(self.filtereddomainsFile, 'a') as w:
                w.write(
                    f"{url} {domain} words: {words} lines: {lines} chars: {chars}\n")

    async def getAllIps(self):
        for url in self.urllist:
            await self.getAllDomainsFromUrl(url)

    async def makeItSo(self):
        logging.info("Checking for open ports")
        async with aiohttp.ClientSession():
            await self.checkForOpenPorts()
            logging.info("Checking for domains")
            tasks = [self.getAllDomainsFromUrl(url) for url in self.urllist]
            await asyncio.gather(*tasks)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-d", "--domain", required=True,
                           help="Domain to bruteforce")
    argparser.add_argument("-i", "--iplist", required=True,
                           help="File containing list of IPs")
    argparser.add_argument(
        "-w", "--wordlist", required=True, help="Wordlist to use")
    argparser.add_argument("-o", "--output", required=True, help="Output file")
    argparser.add_argument("-p", "--ports", required=False,
                           help="Ports to scan. if left out, it will scan 80, 8080, 443, 8443, 4443")
    argparser.add_argument("-l", "--loglevel", required=False,
                           help="Log level, default is info (example: debug, info, warning, error, critical)")
    args = argparser.parse_args()
    if args.loglevel:
        logLevel(args.loglevel)
    else:
        logLevel()
    if args.ports:
        ports = [int(port) for port in args.ports.split(",")]
    else:
        ports = [80, 8080, 443, 8443, 4443]
    vhosts = Vhosts(domain=args.domain, iplistFile=args.iplist,
                    wordlist=args.wordlist, ports=ports, outputFolder=args.output)

    asyncio.run(vhosts.makeItSo())
    vhosts.saveAllDataToFile()
