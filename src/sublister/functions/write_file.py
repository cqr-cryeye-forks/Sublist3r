import os

from src.sublister.classes.colors import Colors


def write_file(filename, subdomains):
    # saving subdomains results to output file
    print("%s[-] Saving results to file: %s%s%s%s" % (Colors.YELLOW, Colors.WHITE, Colors.RED, filename, Colors.WHITE))
    with open(str(filename), 'wt') as f:
        for subdomain in subdomains:
            f.write(subdomain + os.linesep)
