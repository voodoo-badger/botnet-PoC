#!/usr/bin/env python3

"""
Title: scan.py
Author: PiningNorwegianBlue
Date: August 1st, 2019
"""

import nmap
import argparse
from termcolor import colored
import asyncio
import time


async def _nmap_scan(target, port):
    """
    Nmap module is using the -sC and -sV options for scanning
    :param target:  The IP address to scan
    :param port:    The port to scan
    :return:        Status and information about the running service
    """
    nscan = nmap.PortScanner()
    nscan.scan(target, port, arguments="-sC -sV")
    state = nscan[target]["tcp"][int(port)]["state"]
    service_name = nscan[target]["tcp"][int(port)]["name"]
    product = nscan[target]["tcp"][int(port)]["product"]
    version = nscan[target]["tcp"][int(port)]["version"]
    if state == "open":
        print("-" * 100)
        print(colored("[+] Host: {} Port: {:>3}\t {} version {:>10}\tState: {:>5}".format
                      (target,
                       port,
                       product,
                       version,
                       state),
                      "green"))

        if service_name == "ssh":  # Actions that only work with information received from the SSH service
            hostkey = nscan[target]["tcp"][int(port)]["script"]["ssh-hostkey"]
            print(colored("{}\n".format(hostkey), "magenta"))
            with open("hosts.txt", "r") as r:
                """
                Opens or creates the hosts.txt file in read mode, checks the addresses (if any).
                Changes the value of append to False if address is found.
                Appends the address to hosts.txt if append still True after file is read.
                """
                append = True
                for item in r.readlines():
                    if target in item:
                        append = False
                if append:
                    with open("hosts.txt", "a+") as w:
                        w.seek(0)
                        w.write("{}".format(target))
                        w.write("\n")
        elif service_name == "http":  # This could be skipped entirely and may be omitted in the final version
            title = nscan[target]["tcp"][int(port)]["script"]["http-title"]
            print(colored("\t{}\n".format(title), "magenta"))
        else:
            return

    else:
        print("-" * 100)
        print(colored("[-] Host: {}\t Port: {:>3} - Service: {:10}\tState: {:>5}".format
                      (target,
                       port,
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
                        type=int,
                        help="Specify target port.")
    parser.add_argument("-r", "--range",
                        dest="range",
                        type=int,
                        required=False,
                        default=False,
                        help="Specify an optional end port to scan for range.")
    args = parser.parse_args()
    targets = str(args.target).split(",")
    # Will use threading if more than one port is specified
    loop = asyncio.get_event_loop()
    sport = args.port
    eport = args.range
    start_time = time.time()
    for t in targets:
            if args.range:  # Create a port range to scan only if -r option is used
                port_range = range(sport, eport + 1)
                try:
                    for port in port_range:
                        loop.run_until_complete(_nmap_scan(t, str(port)))
                except Exception as e:
                    print(e)
            else:
                loop.run_until_complete(_nmap_scan(t, str(sport)))
    loop.close()
    print(time.time() - start_time)


if __name__ == "__main__":
    main()
