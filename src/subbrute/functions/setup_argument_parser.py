import argparse
import os
from argparse import Namespace


def setup_argument_parser(base_path: str) -> Namespace:
    """Настраивает парсер аргументов командной строки."""
    parser = argparse.ArgumentParser(
        description="Subdomain brute force tool",
        usage="%(prog)s [options] [target]"
    )

    # Взаимоисключающая группа для target и targets_file
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "target",
        nargs="?",
        help="Target domain to brute force (e.g., example.com)"
    )
    target_group.add_argument(
        "--targets_file",
        default="",
        help="File with newline-delimited list of domains to brute force"
    )

    parser.add_argument(
        "--subs",
        default=os.path.join(base_path, "names.txt"),
        help="List of subdomains, default='names.txt'"
    )
    parser.add_argument(
        "--resolvers",
        default=os.path.join(base_path, "resolvers.txt"),
        help="List of DNS resolvers, default='resolvers.txt'"
    )
    parser.add_argument(
        "--output",
        help="Output to file (Greppable Format)"
    )
    parser.add_argument(
        "--json",
        help="Output to file (JSON Format)"
    )
    parser.add_argument(
        "--ipv4",
        action="store_true",
        default=False,
        help="Print all IPv4 addresses for subdomains"
    )
    parser.add_argument(
        "--type",
        help="DNS record type (e.g., CNAME, AAAA, TXT, SOA, MX)"
    )
    parser.add_argument(
        "--process_count",
        default=16,
        type=int,
        help="Number of lookup threads, default=16"
    )
    parser.add_argument(
        "--filter_subs",
        default="",
        help="File with domain names to filter into sorted subdomains"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Print debug information"
    )
    args = parser.parse_args()

    # Проверка существования файлов
    for arg, name in [
        (args.subs, "--subs"),
        (args.resolvers, "--resolvers"),
        (args.targets_file, "--targets_file"),
        (args.filter_subs, "--filter_subs")
    ]:
        if arg and not os.path.isfile(arg):
            parser.error(f"{name}: File '{arg}' does not exist")

    return args