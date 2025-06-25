import dns.resolver
import multiprocessing
import random
import sys
import uuid

import dns.rdatatype
import dns.rdatatype
import dns.resolver
import dns.resolver

from src.subbrute.functions.signal_init import signal_init
from src.subbrute.functions.trace import trace
import queue

class verify_nameservers(multiprocessing.Process):

    def __init__(self, target, record_type, resolver_q, resolver_list, wildcards):
        multiprocessing.Process.__init__(self, target=self.run)
        self.daemon = True
        signal_init()

        self.time_to_die = False
        self.resolver_q = resolver_q
        self.wildcards = wildcards
        # Do we need wildcards for other types of records?
        # This needs testing!
        self.record_type = "A"
        if record_type == "AAAA":
            self.record_type = record_type
        self.resolver_list = resolver_list
        resolver = dns.resolver.Resolver()
        # The domain provided by the user.
        self.target = target
        # 1 website in the world,  modify the following line when this status changes.
        # www.google.cn,  I'm looking at you ;)
        self.most_popular_website = "www.google.com"
        # We shouldn't need the backup_resolver, but we we can use them if need be.
        # We must have a resolver,  and localhost can work in some environments.
        self.backup_resolver = resolver.nameservers + ['127.0.0.1', '8.8.8.8', '8.8.4.4']
        # Ideally a nameserver should respond in less than 1 sec.
        resolver.timeout = 1
        resolver.lifetime = 1
        try:
            # Lets test the letancy of our connection.
            # Google's DNS server should be an ideal time test.
            resolver.nameservers = ['8.8.8.8']
            resolver.query(self.most_popular_website, self.record_type)
        except:
            # Our connection is slower than a junebug in molasses
            resolver = dns.resolver.Resolver()
        self.resolver = resolver

    def end(self):
        self.time_to_die = True

    # This process cannot block forever,  it  needs to check if its time to die.
    def add_nameserver(self, nameserver):
        keep_trying = True
        while not self.time_to_die and keep_trying:
            try:
                self.resolver_q.put(nameserver, timeout=1)
                trace("Added nameserver:", nameserver)
                keep_trying = False
            except Exception as e:
                if type(e) == queue.Full or str(type(e)) == "<class 'queue.Full'>":
                    keep_trying = True

    def verify(self, nameserver_list):
        added_resolver = False
        for server in nameserver_list:
            if self.time_to_die:
                # We are done here.
                break
            server = server.strip()
            if server:
                self.resolver.nameservers = [server]
                try:
                    # test_result = self.resolver.query(self.most_popular_website, "A")
                    # should throw an exception before this line.
                    if True:  # test_result:
                        # Only add the nameserver to the queue if we can detect wildcards.
                        if (self.find_wildcards(self.target)):  # and self.find_wildcards(".com")
                            # wildcards have been added to the set, it is now safe to be added to the queue.
                            # blocking queue,  this process will halt on put() when the queue is full:
                            self.add_nameserver(server)
                            added_resolver = True
                        else:
                            trace("Rejected nameserver - wildcard:", server)
                except Exception as e:
                    # Rejected server :(
                    trace("Rejected nameserver - unreliable:", server, type(e))
        return added_resolver

    def run(self):
        # Every user will get a different set of resovlers, this helps Colors.REDistribute traffic.
        random.shuffle(self.resolver_list)
        if not self.verify(self.resolver_list):
            # This should never happen,  inform the user.
            sys.stderr.write('Warning: No nameservers found, trying fallback list.\n')
            # Try and fix it for the user:
            self.verify(self.backup_resolver)
        # End of the resolvers list.
        try:
            self.resolver_q.put(False, timeout=1)
        except:
            pass

    # Only add the nameserver to the queue if we can detect wildcards.
    # Returns False on error.
    def find_wildcards(self, host):
        # We want sovle the following three problems:
        # 1)The target might have a wildcard DNS record.
        # 2)The target maybe using geolocaiton-aware DNS.
        # 3)The DNS server we are testing may respond to non-exsistant 'A' records with advertizements.
        # I have seen a CloudFlare Enterprise customer with the first two conditions.
        try:
            # This is case #3,  these spam nameservers seem to be more trouble then they are worth.
            wildtest = self.resolver.query(uuid.uuid4().hex + ".com", "A")
            if len(wildtest):
                trace("Spam DNS detected:", host)
                return False
        except:
            pass
        test_counter = 8
        looking_for_wildcards = True
        while looking_for_wildcards and test_counter >= 0:
            looking_for_wildcards = False
            # Don't get lost, this nameserver could be playing tricks.
            test_counter -= 1
            try:
                testdomain = "%s.%s" % (uuid.uuid4().hex, host)
                wildtest = self.resolver.query(testdomain, self.record_type)
                # This 'A' record may contain a list of wildcards.
                if wildtest:
                    for w in wildtest:
                        w = str(w)
                        if w not in self.wildcards:
                            # wildcards were detected.
                            self.wildcards[w] = None
                            # We found atleast one wildcard, look for more.
                            looking_for_wildcards = True
            except Exception as e:
                if type(e) == dns.resolver.NXDOMAIN or type(e) == dns.name.EmptyLabel:
                    # not found
                    return True
                else:
                    # This resolver maybe flakey, we don't want it for our tests.
                    trace("wildcard exception:", self.resolver.nameservers, type(e))
                    return False
        # If we hit the end of our depth counter and,
        # there are still wildcards, then reject this nameserver because it smells bad.
        return (test_counter >= 0)
