from gnutella_p2p import Start_P2P
from multiprocessing import Process
import sys, os, signal

p2p_process = None

def signal_handler(signalNumber, frame):
    global p2p_process
    p2p_process.join()
    print("FINITO")
    sys.exit(0)

print(os.getpid())

p2p_process = Process(target=Start_P2P, args=(None, None, None, ))
p2p_process.start()
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTSTP, signal_handler)
while True:
    pass
