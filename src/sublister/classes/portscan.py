import socket
import threading

from src.sublister.classes.colors import Colors


class portscan():
    def __init__(self, subdomains, ports):
        self.subdomains = subdomains
        self.ports = ports
        self.threads = 20
        self.lock = threading.BoundedSemaphore(value=self.threads)

    def port_scan(self, host, ports):
        openports = []
        self.lock.acquire()
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, int(port)))
                if result == 0:
                    openports.append(port)
                s.close()
            except Exception:
                pass
        self.lock.release()
        if len(openports) > 0:
            print(
                "%s%s%s - %sFound open ports:%s %s%s%s" % (Colors.GREEN, host, Colors.WHITE, Colors.RED, Colors.WHITE, Colors.YELLOW,
                                                           ', '.join(openports), Colors.WHITE))

    def run(self):
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.port_scan, args=(subdomain, self.ports))
            t.start()
