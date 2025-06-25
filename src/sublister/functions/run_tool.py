import multiprocessing
import os
import re
from urllib.parse import urlparse

from src.subbrute.functions.print_target import print_target
from src.sublister.classes.ask_enum import AskEnum
from src.sublister.classes.baidu_enum import BaiduEnum
from src.sublister.classes.bing_enum import BingEnum
from src.sublister.classes.colors import Colors
from src.sublister.classes.crt_search import CrtSearch
from src.sublister.classes.dnsdumpster import DNSdumpster
from src.sublister.classes.google_enum import GoogleEnum
from src.sublister.classes.netcraft_enum import NetcraftEnum
from src.sublister.classes.passive_dns import PassiveDNS
from src.sublister.classes.portscan import portscan
from src.sublister.classes.threat_crowd import ThreatCrowd
from src.sublister.classes.virustotal import Virustotal
from src.sublister.classes.yahoo_enum import YahooEnum
from src.sublister.functions.subdomain_sorting_key import subdomain_sorting_key
from src.sublister.functions.write_file import write_file


def run_tool(domain, threads, savefile, ports, silent, verbose, enable_bruteforce, engines):
    bruteforce_list = set()
    search_list = set()

    subdomains_queue = multiprocessing.Manager().list()

    # Check Bruteforce Status
    if enable_bruteforce or enable_bruteforce is None:
        enable_bruteforce = True

    # Validate domain
    domain_check = re.compile("^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        if not silent:
            print(Colors.RED + "Error: Please enter a valid domain" + Colors.WHITE)
        return []

    if not domain.startswith('http://') or not domain.startswith('https://'):
        domain = 'http://' + domain

    parsed_domain = urlparse(domain)

    if not silent:
        print(Colors.BLUE + "[-] Enumerating subdomains now for %s" % parsed_domain.netloc + Colors.WHITE)

    if verbose and not silent:
        print(Colors.YELLOW + "[-] verbosity is enabled, will show the subdomains results in realtime" + Colors.WHITE)

    supported_engines = {'baidu': BaiduEnum,
                         'yahoo': YahooEnum,
                         'google': GoogleEnum,
                         'bing': BingEnum,
                         'ask': AskEnum,
                         'netcraft': NetcraftEnum,
                         'dnsdumpster': DNSdumpster,
                         'virustotal': Virustotal,
                         'threatcrowd': ThreatCrowd,
                         'ssl': CrtSearch,
                         'passivedns': PassiveDNS
                         }

    chosenEnums = []

    if engines is None:
        chosenEnums = [
            BaiduEnum, YahooEnum, GoogleEnum, BingEnum, AskEnum,
            NetcraftEnum, DNSdumpster, Virustotal, ThreatCrowd,
            CrtSearch, PassiveDNS
        ]
    else:
        engines = engines.split(',')
        for engine in engines:
            if engine.lower() in supported_engines:
                chosenEnums.append(supported_engines[engine.lower()])

    # Start the engines enumeration
    enums = [enum(domain, [], q=subdomains_queue, silent=silent, verbose=verbose) for enum in chosenEnums]
    for enum in enums:
        enum.start()
    for enum in enums:
        enum.join()

    subdomains = set(subdomains_queue)
    for subdomain in subdomains:
        search_list.add(subdomain)

    if enable_bruteforce:
        if not silent:
            print(Colors.GREEN + "[-] Starting bruteforce module now using subbrute.." + Colors.WHITE)
        record_type = False
        path_to_file = os.path.dirname(os.path.realpath(__file__))
        subs = os.path.join(path_to_file, 'subbrute', 'names.txt')
        resolvers = os.path.join(path_to_file, 'subbrute', 'resolvers.txt')
        process_count = threads
        output = False
        json_output = False
        bruteforce_list = print_target(parsed_domain.netloc, record_type, subs, resolvers, process_count,
                                       output, json_output, search_list, verbose)

    subdomains = search_list.union(bruteforce_list)

    if subdomains:
        subdomains = sorted(subdomains, key=subdomain_sorting_key)

        if savefile:
            write_file(savefile, subdomains)

        if not silent:
            print(Colors.YELLOW + "[-] Total Unique Subdomains Found: %s" % len(subdomains) + Colors.WHITE)

        if ports:
            if not silent:
                print(Colors.GREEN + "[-] Start port scan now for the following ports: %s%s" % (Colors.YELLOW,
                                                                                                ports) + Colors.WHITE)
            ports = ports.split(',')
            pscan = portscan(subdomains, ports)
            pscan.run()

        elif not silent:
            for subdomain in subdomains:
                print(Colors.GREEN + subdomain + Colors.WHITE)
    return subdomains
