import signal

from src.subbrute.functions.killproc import killproc


def signal_init():
    #Escliate signal to prevent zombies.
    signal.signal(signal.SIGINT, killproc)
    try:
        signal.signal(signal.SIGTSTP, killproc)
        signal.signal(signal.SIGQUIT, killproc)
    except:
        #Windows
        pass
