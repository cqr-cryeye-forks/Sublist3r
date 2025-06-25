import re
import threading

from src.sublister.classes.colors import Colors
from src.sublister.classes.enumrator_base_threaded import enumratorBaseThreaded

class Virustotal(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.virustotal.com/en/domain/{domain}/information/'
        self.engine_name = "Virustotal"
        self.lock = threading.Lock()
        self.q = q
        super(Virustotal, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    # the main send_req need to be rewritten
    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            self.print_(e)
            resp = None

        return self.get_response(resp)

    # once the send_req is rewritten we don't need to call this function, the stock one should be ok
    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.send_req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        link_regx = re.compile('<div class="enum.*?">.*?<a target="_blank" href=".*?">(.*?)</a>', re.S)
        try:
            links = link_regx.findall(resp)
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (Colors.RED, self.engine_name, Colors.WHITE, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
