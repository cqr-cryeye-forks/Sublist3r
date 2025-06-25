import re


def extract_hosts(data, hostname):
    #made a global to avoid re-compilation
    host_match = re.compile(r"((?<=[\s])[a-zA-Z0-9_-]+\.(?:[a-zA-Z0-9_-]+\.?)+(?=[\s]))")
    ret = []
    hosts = re.findall(host_match, data)
    for fh in hosts:
        host = fh.rstrip(".")
        #Is this host in scope?
        if host.endswith(hostname):
            ret.append(host)
    return ret
