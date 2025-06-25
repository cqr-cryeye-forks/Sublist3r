import ctypes
import os
import sys


def killproc(signum = 0, frame = 0, pid = False):
    if not pid:
        pid = os.getpid()
    if sys.platform.startswith('win'):
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(1, 0, pid)
            kernel32.TerminateProcess(handle, 0)
        except:
            #Oah windows.
            pass
    else:
        os.kill(pid, 9)
