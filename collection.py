#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: collection.py
Author: PiningNorwegianBlue
Date: August 5th, 2019
"""
import nmap
from termcolor import colored
import shodan_scan
from pexpect import pxssh
from threading import *
import os


con_lock = Semaphore(value=5)


class Scan:
    """
    Host and port scanner using the NMAP module for service detection.
    """
    def __init__(self, target, verbose):
        self.target = target  # Target IP address
        self.port = "22"  # Only scans port 22 by default
        self.verbose = verbose  # Only prints results to screen if the verbose option chosen when running initialize.py

    def _scan(self):
        """
        Scanning the target. Takes IP address as input, port number is static.
        """
        try:
            nscan = nmap.PortScanner()
            nscan.scan(self.target, self.port, arguments="-sC -sV")  # Scanner is started with arguments
            state = nscan[self.target]["tcp"][int(self.port)]["state"]
            service_name = nscan[self.target]["tcp"][int(self.port)]["name"]
            product = nscan[self.target]["tcp"][int(self.port)]["product"]
            version = nscan[self.target]["tcp"][int(self.port)]["version"]
            if self.verbose:
                if state == "open":
                    print("-" * 100)
                    print(colored("[+] Host: {} Port: {:>3}\t {} version {:>10}\tState: {:>5}".format
                                  (self.target,
                                   self.port,
                                   product,
                                   version,
                                   state),
                                  "green"))
                    if service_name == "ssh":  # Actions that only happen with information received from the SSH service
                        hostkey = nscan[self.target]["tcp"][int(self.port)]["script"]["ssh-hostkey"]
                        print(colored("{}\n".format(hostkey), "magenta"))
                        # Checking if the IP address is within the hosts.txt file and if it exists
                        path = "./hosts.txt"
                        mode = "a+" if os.path.exists(path) else os.mknod(path)
                        with open(path, "r+") as r:
                            """
                            Opens or creates the hosts.txt file in read mode, checks the addresses (if any).
                            Changes the value of append to False if address is found.
                            Appends the address to hosts.txt if append still True after file is read.
                            """
                            append = True
                            for item in r.readlines():
                                if self.target in item:
                                    append = False
                            if append:
                                with open(path, "a+") as w:
                                    w.seek(0)
                                    w.write("{}\n".format(self.target))
                elif KeyError:
                    print("-" * 100)
                    print(colored("[-] Host: {}\t Port: {:>3}\t - Service: {:10}\tState: {:>5}".format
                                  (self.target,
                                   self.port,
                                   service_name,
                                   state),
                                  "red"))
            # Skips printing findings (no -v option used)
            else:
                if state == "open":
                    if service_name == "ssh":  # Actions that only work with information received from the SSH service
                        path = "./hosts.txt"
                        mode = "a+" if os.path.exists(path) else os.mknod(path)
                        with open(path, "r+") as r:
                            """
                            Opens or creates the hosts.txt file in read mode, checks the addresses (if any).
                            Changes the value of append to False if address is found.
                            Appends the address to hosts.txt if append still True after file is read.
                            """
                            append = True
                            for item in r.readlines():
                                if self.target in item:
                                    append = False
                            if append:
                                with open(path, "a+") as w:
                                    w.seek(0)
                                    w.write("{}\n".format(self.target))
        except Exception as e:
            print("{} is not a recognised IPv4 address".format(e))


class Bot:
    # Initializes new target
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.session = self.ssh()

    # Handles SSH connection to target
    def ssh(self):
            bot = pxssh.pxssh()
            bot.login(self.host, self.user, self.password, sync_multiplier=2, sync_original_prompt=False)
            return bot

    # Handles sending commands to target
    def send_command(self, command):
        self.session.sendline(command)
        self.session.prompt()
        print(("-" * 50), f"{self.host}", ("-" * 50))
        return str(self.session.before.decode())


def shodan_gather(verbose):
    shodan_scan.main(verbose)
