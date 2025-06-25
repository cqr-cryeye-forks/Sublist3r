from src.sublister.functions.parser import parse_args
from src.sublister.functions.run_tool import run_tool


def main():
    args = parse_args()
    domain = args.domain
    threads = args.threads
    savefile = args.output
    ports = args.ports
    enable_bruteforce = args.bruteforce
    verbose = args.verbose
    engines = args.engines
    if verbose or verbose is None:
        verbose = True
    res = run_tool(domain, threads, savefile, ports, silent=False, verbose=verbose, enable_bruteforce=enable_bruteforce,
                   engines=engines)
