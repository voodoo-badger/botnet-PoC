#!/usr/bin/env python3
"""
Title: scan.py
Author: PiningNorwegianBlue
Date: August 1st, 2019
"""
import nmap
import argparse
from termcolor import colored
import os


class Scan:
    def __init__(self, target, port):
        self.target = target
        self.port = port

    def _scan(self):
        """
        Nmap module is using the -sC and -sV options for scanning
        :param target:  The IP address to scan
        :param port: The port to scan
        :return: status and information about the running service
        """

        nscan = nmap.PortScanner()
        nscan.scan(self.target, self.port, arguments="-sC -sV")
        state = nscan[self.target]["tcp"][int(self.port)]["state"]
        service_name = nscan[self.target]["tcp"][int(self.port)]["name"]
        product = nscan[self.target]["tcp"][int(self.port)]["product"]
        version = nscan[self.target]["tcp"][int(self.port)]["version"]
        if state == "open":
            print("-" * 100)
            print(colored("[+] Host: {} Port: {:>3}\t {} version {:>10}\tState: {:>5}".format
                          (self.target,
                           self.port,
                           product,
                           version,
                           state),
                          "green"))
            if service_name == "ssh":  # Actions that only work with information received from the SSH service
                hostkey = nscan[self.target]["tcp"][int(self.port)]["script"]["ssh-hostkey"]
                print(colored("{}\n".format(hostkey), "magenta"))
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


def main():
    """
    Argument parser. Threading is implemented if more than one host or a range of ports is defined
    :return:
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target",
                        dest="target",
                        type=str,
                        help="Specify target host or hosts separated by comma.")
    parser.add_argument("-p", "--port",
                        dest="port",
                        type=str,
                        required=False,
                        default="22, 2222",
                        help="Specify target port.")
    parser.add_argument("-r", "--range",
                        dest="range",
                        type=int,
                        required=False,
                        default=False,
                        help="Specify an optional end port to scan for range.")
    args = parser.parse_args()
    targets = str(args.target).split(",")
    print(targets)
    ports = str(args.port).split(",")
    for t in targets:
        for p in ports:
            s = Scan(t, p)
            s._scan()


if __name__ == "__main__":
    main()
