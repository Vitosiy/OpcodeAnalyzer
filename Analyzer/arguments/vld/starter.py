import os
import time


class VldStarter:
    def __init__(self):
        ...

    def start_for_time(self, time_to_work: int):
        os.system("sh ../Scripts/START_VLD.SH")
        time.sleep(time_to_work)
        self.stop()

    @staticmethod
    def stop():
        os.system("sh ../Scripts/STOP_VLD.SH")

    def start(self):
        os.system("sh ../Scripts/START_VLD.SH")
        result = input()
        if result == 's'.lower():
            self.stop()

