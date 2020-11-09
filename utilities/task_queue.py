from threading import Thread
from queue import Queue
import ctypes


class TaskQueue(Thread):
    def __init__(self):
        self.taskqueue = Queue()
        Thread.__init__(self)
    
    def run(self):
        while(True):
            if self.taskqueue.empty():
                continue
            thread = self.taskqueue.get()
            thread.start()
            thread.join()

    def put(self, thread):
        self.taskqueue.put(thread)

    def raise_exception(self): 
        thread_id = self.get_id() 
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 
              ctypes.py_object(SystemExit)) 
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0) 
            print('Exception raise failure')