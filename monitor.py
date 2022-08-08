# author: fe1w0
from utils import *
import os
     
if __name__ == "__main__":
    # os.system("clear")
    monitor_config = config.monitor_config
    while(True):
        monitor(monitor_config)
        time.sleep(monitor_config["refresh_time"])
