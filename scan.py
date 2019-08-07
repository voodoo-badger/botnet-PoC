#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Title: MaScanMan.py
Author: PiningNorwegianBlue
Date: August 1st, 2019
"""

import nmap
import argparse
from termcolor import colored
from threading import *
screen_lock = Semaphore(value=1)


def _nmap_scan(target, port):
    """
    Nmap module is using the -sC and -sV options for scanning
    :param target:
    :param port:     #print(nscan.scan(target, port, arguments="-sC -sV"))
    :return:
    """
    nscan = nmap.PortScanner()
    nscan.scan(target, port, arguments="-sC -sV")
    state = nscan[target]["tcp"][int(port)]["state"]
    service_name = nscan[target]["tcp"][int(port)]["name"]
    product = nscan[target]["tcp"][int(port)]["product"]
    version = nscan[target]["tcp"][int(port)]["version"]
    try:
        if state == "open":
            screen_lock.acquire()
            print("-" * 50)
            print(colored("[+] Host: {} Port: {}\t {} version {}\tState: {}".format
                          (target,
                           port,
                           product,
                           version,
                           state),
                          "green"))
            screen_lock.release()

            if service_name == "ssh":
                # Printing banner information
                hostkey = nscan[target]["tcp"][int(port)]["script"]["ssh-hostkey"]
                screen_lock.acquire()
                print(colored(" {}\n".format(hostkey), "magenta"))
                screen_lock.release()
                with open("hosts.txt", "r") as r:
                    append = True
                    for item in r.readlines():
                        if target in item:
                            append = False
                    if append:
                        with open("hosts.txt", "a+") as w:
                            w.seek(0)
                            w.write("{}".format(target))
                            w.write("\n")
            elif service_name == "http":
                # Printing banner information
                title = nscan[target]["tcp"][int(port)]["script"]["http-title"]
                screen_lock.acquire()
                print(colored("\t{}\n".format(title), "magenta"))
                screen_lock.release()
            else:
                return

        else:
            screen_lock.acquire()
            print("-" * 50)
            print(colored("[-] Host: {} Port: {}\t Service: {}\tState: {}".format
                          (target,
                           port,
                           service_name,
                           state),
                          "red"))
    except Exception as e:
        print(e)
    finally:
        screen_lock.release()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", type=str,
                        help="Specify target host or hosts separated by comma.")
    parser.add_argument("-p", "--port", dest="port", type=str,
                        help="Specify target port or ports separated by comma.")
    args = parser.parse_args()
    targets = str(args.target).split(",")
    ports = str(args.port).split(",")
    sport = int(ports[0])

    # Will use threading if more than one port is specified
    try:
        for t in targets:
            try:
                eport = int(ports[1])
                port_range = range(sport, eport + 1)
                for port in port_range:
                    thread = Thread(target=_nmap_scan, args=(t, str(port)))
                    thread.start()
            except IndexError:
                _nmap_scan(t, str(sport))
    except IndexError:
        _nmap_scan(targets, str(sport))


if __name__ == "__main__":
    main()
