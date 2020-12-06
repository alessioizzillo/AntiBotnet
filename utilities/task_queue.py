import threading
from queue import Queue
import ctypes


class TaskQueue(threading.Thread):
    def __init__(self):
        self.current_thread = None
        self._stopper = threading.Event()
        self.taskqueue = Queue()
        threading.Thread.__init__(self)
    
    def stop(self):
        self._stopper.set()

    def run(self):
        while not self._stopper.isSet():
            if self.taskqueue.empty():
                continue
            self.current_thread = self.taskqueue.get()
            self.current_thread.start()
            try:
                self.current_thread.join()
            except:
                pass
        print("\n---ANTIBOTNET (EXIT)---\n")

    def put(self, thread):
        self.taskqueue.put(thread)