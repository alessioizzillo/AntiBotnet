import threading
from queue import Queue
import ctypes
from csv import writer
from time import perf_counter, sleep


class TaskQueue(threading.Thread):
    def __init__(self, mode, thread_name):
        self.mode = mode
        self.thread_name = thread_name
        self.current_thread = None
        self._stopper = threading.Event()
        self._stopper_when_empty = threading.Event()
        self.taskqueue = Queue()
        threading.Thread.__init__(self)
    
    def stop(self):
        self._stopper.set()

    def stop_when_empty(self):
        self._stopper_when_empty.set()

    def run(self):
        while not self._stopper.isSet():
            if self.taskqueue.empty():
                if self._stopper_when_empty.isSet():
                    break
                else:
                    continue
            self.current_thread = self.taskqueue.get()
            start_time = perf_counter()
            self.current_thread.start()
            try:
                self.current_thread.join()
                end_time = perf_counter()

                if (self.mode == 'test' or self.mode == 'test_no_gbd') and self.thread_name == 'BotnetDetection':     
                    with open("test_results.csv", 'a+', newline='') as write_obj:
                        csv_writer = writer(write_obj)
                        csv_writer.writerow(["FBD", end_time-start_time, -1, \
                            self.current_thread.fbd_exec_time, -1, self.current_thread.n_true_pos, \
                            self.current_thread.n_true_neg, self.current_thread.n_false_pos, \
                            self.current_thread.n_false_neg, self.current_thread.len_results])
                
                elif self.mode == 'test' and self.thread_name == 'IncrementalLearning':
                    with open("test_results.csv", 'a+', newline='') as write_obj:
                        csv_writer = writer(write_obj)
                        csv_writer.writerow(["GBD", -1, end_time-start_time, -1, \
                            self.current_thread.gbd_exec_time, self.current_thread.n_true_pos, \
                            self.current_thread.n_true_neg, self.current_thread.n_false_pos, \
                            self.current_thread.n_false_neg, self.current_thread.len_results])                    

            except:
                pass

    def put(self, thread):
        self.taskqueue.put(thread)