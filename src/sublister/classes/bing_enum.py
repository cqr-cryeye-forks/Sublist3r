import re
from urllib.parse import urlparse

from src.sublister.classes.colors import Colors
from src.sublister.classes.enumrator_base_threaded import enumratorBaseThreaded

class BingEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'
        self.engine_name = "Bing"
        self.MAX_DOMAINS = 30
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q, silent=silent)
        self.q = q
        self.verbose = verbose
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<li class="b_algo"><h2><a href="(.*?)"')
        link_regx2 = re.compile('<div class="b_title"><h2><a href="(.*?)"')
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2

            for link in links_list:
                link = re.sub('<(\/)?strong>|<span.*?>|<|>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (Colors.RED, self.engine_name, Colors.WHITE, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def generate_query(self):
        if self.subdomains:
            fmt = 'domain:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "domain:{domain} -www.{domain}".format(domain=self.domain)
        return query
