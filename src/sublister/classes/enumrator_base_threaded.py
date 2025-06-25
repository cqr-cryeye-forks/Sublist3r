import multiprocessing
import threading

from src.sublister.classes.enumrator_base import enumratorBase


class enumratorBaseThreaded(multiprocessing.Process, enumratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, q=None, lock=threading.Lock(), silent=False, verbose=True):
        subdomains = subdomains or []
        enumratorBase.__init__(self, base_url, engine_name, domain, subdomains, silent=silent, verbose=verbose)
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)
