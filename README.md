FunWithVhosts

A tool designed to efficiently check for virtual hosts across multiple IP addresses.

Description

FunWithVhosts automates the process of identifying virtual hosts on given IP addresses. The script checks for open ports, specifically web server ports, and then tries to retrieve content using a list of possible subdomains for a specified domain. It uses threading for efficient scanning and provides a detailed output of its findings.

Features

Concurrent scanning using threading.
Checks for open ports 80, 8080, 443, 8443, and 4443 by default.
Customizable port scanning.
Uses a wordlist to try possible subdomains on the target domain.
Outputs detailed results including status codes and content lengths.
Filters results to highlight significant findings.
Prerequisites

Installation

Clone the repository:
git clone git@github.com:jad2121/FunWithVhosts.git
Install the required Python libqraries:
pip install -r requirements.txt

usage: vhosts.py [-h] -d DOMAIN -i IPLIST -w WORDLIST -o OUTPUT [-p PORTS] [-l LOGLEVEL]

options:
-h, --help show this help message and exit
-d DOMAIN, --domain DOMAIN
Domain to bruteforce
-i IPLIST, --iplist IPLIST
File containing list of IPs
-w WORDLIST, --wordlist WORDLIST
Wordlist to use
-o OUTPUT, --output OUTPUT
Output file
-p PORTS, --ports PORTS
Ports to scan. if left out, it will scan 80, 8080, 443, 8443, 4443
-l LOGLEVEL, --loglevel LOGLEVEL
Log level, default is info (example: debug, info, warning, error, critical)
Example

python vhosts.py -d adjust.com -i ips.txt -w ~/bug_bounty/wordlists/subdomains/best-dns-wordlist.txt -p 443 -o vhostoutput -l debug

Contributing

I did not work alone. I had two important contributors: chatGPT and github copilot.

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
