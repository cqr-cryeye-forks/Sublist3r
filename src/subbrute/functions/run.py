import multiprocessing
import os
import sys

from src.subbrute.classes.lookup import lookup
from src.subbrute.classes.verify_nameservers import verify_nameservers
from src.subbrute.functions.check_open import check_open
from src.subbrute.functions.killproc import killproc
from src.subbrute.functions.trace import trace
import queue

def run(target, record_type = None, subdomains = "names.txt", resolve_list = "resolvers.txt", process_count = 16):
    subdomains = check_open(subdomains)
    resolve_list = check_open(resolve_list)
    if (len(resolve_list) / 16) < process_count:
        sys.stderr.write('Warning: Fewer than 16 resovlers per thread, consider adding more nameservers to resolvers.txt.\n')
    if os.name == 'nt':
        wildcards = {}
        spider_blacklist = {}
    else:
        wildcards = multiprocessing.Manager().dict()
        spider_blacklist = multiprocessing.Manager().dict()
    in_q = multiprocessing.Queue()
    out_q = multiprocessing.Queue()
    #have a buffer of at most two new nameservers that lookup processes can draw from.
    resolve_q = multiprocessing.Queue(maxsize = 2)

    #Make a source of fast nameservers avaiable for other processes.
    verify_nameservers_proc = verify_nameservers(target, record_type, resolve_q, resolve_list, wildcards)
    verify_nameservers_proc.start()
    #The empty string
    in_q.put((target, record_type))
    spider_blacklist[target]=None
    #A list of subdomains is the input
    for s in subdomains:
        s = str(s).strip()
        if s:
            if s.find(","):
                #SubBrute should be forgiving, a comma will never be in a url
                #but the user might try an use a CSV file as input.
                s=s.split(",")[0]
            if not s.endswith(target):
                hostname = "%s.%s" % (s, target)
            else:
                #A user might feed an output list as a subdomain list.
                hostname = s
            if hostname not in spider_blacklist:
                spider_blacklist[hostname]=None
                work = (hostname, record_type)
                in_q.put(work)
    #Terminate the queue
    in_q.put(False)
    for i in range(process_count):
        worker = lookup(in_q, out_q, resolve_q, target, wildcards, spider_blacklist)
        worker.start()
    threads_remaining = process_count
    while True:
        try:
            #The output is valid hostnames
            result = out_q.get(True, 10)
            #we will get an empty exception before this runs.
            if not result:
                threads_remaining -= 1
            else:
                #run() is a generator, and yields results from the work queue
                yield result
        except Exception as e:
            #The cx_freeze version uses queue.Empty instead of Queue.Empty :(
            if type(e) == queue.Empty or str(type(e)) == "<class 'queue.Empty'>":
                pass
            else:
                raise(e)
        #make sure everyone is complete
        if threads_remaining <= 0:
            break
    trace("killing nameserver process")
    #We no longer require name servers.
    try:
        killproc(pid = verify_nameservers_proc.pid)
    except:
        #Windows threading.tread
        verify_nameservers_proc.end()
    trace("End")
