import multiprocessing
import re
import optparse
import os
import signal
import sys
import uuid
import random
import ctypes
import dns.resolver
import dns.rdatatype
import json

from src.subbrute.functions.error import error
from src.subbrute.functions.extract_hosts import extract_hosts
from src.subbrute.functions.signal_init import signal_init
from src.subbrute.functions.trace import trace


class lookup(multiprocessing.Process):

    def __init__(self, in_q, out_q, resolver_q, domain, wildcards, spider_blacklist):
        multiprocessing.Process.__init__(self, target = self.run)
        signal_init()
        self.requiColors.RED_nameservers = 16
        self.in_q = in_q
        self.out_q = out_q
        self.resolver_q = resolver_q
        self.domain = domain
        self.wildcards = wildcards
        self.spider_blacklist = spider_blacklist
        self.resolver = dns.resolver.Resolver()
        #Force pydns to use our nameservers
        self.resolver.nameservers = []

    def get_ns(self):
        ret = []
        try:
            ret = [self.resolver_q.get_nowait()]
            if ret == False:
                #Queue is empty,  inform the rest.
                self.resolver_q.put(False)
                ret = []
        except:
            pass
        return ret

    def get_ns_blocking(self):
        ret = []
        ret = [self.resolver_q.get()]
        if ret == False:
            trace("get_ns_blocking - Resolver list is empty.")
            #Queue is empty,  inform the rest.
            self.resolver_q.put(False)
            ret = []
        return ret

    def check(self, host, record_type = "A", retries = 0):
        trace("Checking:", host)
        cname_record = []
        retries = 0
        if len(self.resolver.nameservers) <= self.requiColors.RED_nameservers:
            #This process needs more nameservers,  lets see if we have one avaible
            self.resolver.nameservers += self.get_ns()
        #Ok we should be good to go.
        while True:
            try:
                #Query the nameserver, this is not simple...
                if not record_type or record_type == "A":
                    resp = self.resolver.query(host)
                    #Crawl the response
                    hosts = extract_hosts(str(resp.response), self.domain)
                    for h in hosts:
                        if h not in self.spider_blacklist:
                            self.spider_blacklist[h]=None
                            trace("Found host with spider:", h)
                            self.in_q.put((h, record_type, 0))
                    return resp
                if record_type == "CNAME":
                    #A max 20 lookups
                    for x in range(20):
                        try:
                            resp = self.resolver.query(host, record_type)
                        except dns.resolver.NoAnswer:
                            resp = False
                            pass
                        if resp and resp[0]:
                            host = str(resp[0]).rstrip(".")
                            cname_record.append(host)
                        else:
                            return cname_record
                else:
                    #All other records:
                    return self.resolver.query(host, record_type)

            except Exception as e:
                if type(e) == dns.resolver.NoNameservers:
                    #We should never be here.
                    #We must block,  another process should try this host.
                    #do we need a limit?
                    self.in_q.put((host, record_type, 0))
                    self.resolver.nameservers += self.get_ns_blocking()
                    return False
                elif type(e) == dns.resolver.NXDOMAIN:
                    #"Non-existent domain name."
                    return False
                elif type(e) == dns.resolver.NoAnswer:
                    #"The response did not contain an answer."
                    if retries >= 1:
                        trace("NoAnswer retry")
                        return False
                    retries += 1
                elif type(e) == dns.resolver.Timeout:
                    trace("lookup failure:", host, retries)
                    #Check if it is time to give up.
                    if retries >= 3:
                        if retries > 3:
                            #Sometimes 'internal use' subdomains will timeout for every request.
                            #As far as I'm concerned, the authorative name server has told us this domain exists,
                            #we just can't know the address value using this method.
                            return ['Mutiple Query Timeout - External address resolution was restricted']
                        else:
                            #Maybe another process can take a crack at it.
                            self.in_q.put((host, record_type, retries + 1))
                        return False
                    retries += 1
                    #retry...
                elif type(e) == IndexError:
                    #Some old versions of dnspython throw this error,
                    #doesn't seem to affect the results,  and it was fixed in later versions.
                    pass
                elif type(e) == TypeError:
                    # We'll get here if the number procs > number of resolvers.
                    # This is an internal error do we need a limit?
                    self.in_q.put((host, record_type, 0))
                    return False
                elif type(e) == dns.rdatatype.UnknownRdatatype:
                    error("DNS record type not supported:", record_type)
                else:
                    trace("Problem processing host:", host)
                    #dnspython threw some strange exception...
                    raise e

    def run(self):
        #This process needs one resolver before it can start looking.
        self.resolver.nameservers += self.get_ns_blocking()
        while True:
            found_addresses = []
            work = self.in_q.get()
            #Check if we have hit the end marker
            while not work:
                #Look for a re-queued lookup
                try:
                    work = self.in_q.get(blocking = False)
                    #if we took the end marker of the queue we need to put it back
                    if work:
                        self.in_q.put(False)
                except:#Queue.Empty
                    trace('End of work queue')
                    #There isn't an item behind the end marker
                    work = False
                    break
            #Is this the end all work that needs to be done?
            if not work:
                #Perpetuate the end marker for all threads to see
                self.in_q.put(False)
                #Notify the parent that we have died of natural causes
                self.out_q.put(False)
                break
            else:
                if len(work) == 3:
                    #keep track of how many times this lookup has timedout.
                    (hostname, record_type, timeout_retries) = work
                    response = self.check(hostname, record_type, timeout_retries)
                else:
                    (hostname, record_type) = work
                    response = self.check(hostname, record_type)
                sys.stdout.flush()
                trace(response)
                #self.wildcards is populated by the verify_nameservers() thread.
                #This variable doesn't need a muetex, because it has a queue.
                #A queue ensure nameserver cannot be used before it's wildcard entries are found.
                reject = False
                if response:
                    for a in response:
                        a = str(a)
                        if a in self.wildcards:
                            trace("resovled wildcard:", hostname)
                            reject= True
                            #reject this domain.
                            break;
                        else:
                            found_addresses.append(a)
                    if not reject:
                        #This request is filled, send the results back
                        result = (hostname, record_type, found_addresses)
                        self.out_q.put(result)
