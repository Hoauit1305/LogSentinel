#!/usr/bin/env python3
# gen log automatically on linux
# how to run: sudo ./gen_log.py

import random
import os
import subprocess
import time

print("hello world")

total_event = random.randint(50,100)
count_logs = 0

def auth_log(msg, prio="authpriv.warning"):
    # system logger
    try:
        subprocess.run(["logger", "-p", prio, msg], check=False)
    except Exception:
        pass
# random ip
def rand_ip():
    return f"{random.randint(10,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
# main
while count_logs < total_event:
    ip = rand_ip()
    msg = f'sshd[{os.getpid()}]: Accepted password for test from {ip} port {random.randint(1024,65000)} ssh2'
    auth_log(msg, "authpriv.info") 
    print("[SSH OK]", ip)
    count_logs += 1
    time.sleep(0.02)

# call
print("Done. Generated", count_logs, "events.")