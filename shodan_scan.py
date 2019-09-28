#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: shodan_scan.py
Author: PiningNorwegianBlue
Date: August 5th, 2019
"""
import shodan
import os
from termcolor import colored

"""
shodan_api_key.txt file added to .gitignore to avoid uploading private API key
"""

# Shodan API key here
path_to_api = "./shodan_api_key.txt"


def scan(api, verbose=False):
    api = shodan.Shodan(api)  # Api key issued to shodan.io
    try:
        results = api.search("ssh")  # Search term issued to shodan.io
        #  Writes results to shodan_results.txt
        path = "./shodan_results.txt"
        mode = "a+" if os.path.exists(path) else os.mknod(path)
        for result in results["matches"]:
            ip = result["ip_str"]
            port = result["port"]
            with open(path, "r+") as rr:
                append = True
                for line in rr.readlines():
                    if ip in line:
                        append = False
                if append:
                    with open(path, "a+") as wr:
                        wr.write("{},{}\n".format(ip, port))
            # Print IP address and company name, city/country to screen if verbose
            if verbose:
                print(colored("+ IP: {:<} - Port: {}".format(
                    ip,
                    port),
                    "green"))
                print(colored("\tOrganization: {}".format(
                    result["org"]),
                    "magenta"))
                print(colored("\tLocation: {}, {}\n".format(
                    result["location"]["city"],
                    result["location"]["country_name"]),
                    "magenta"))
        # Total search results
        print("{} results total\n".format(results["total"]))
    except shodan.APIError as e:
        print("Error: {}".format(e))
        exit(0)


def main(verbose):
    try:
        with open(path_to_api, "r") as key:
            SHODAN_API_KEY = key.readline().strip("\n")
            scan(SHODAN_API_KEY, verbose)
    except FileNotFoundError:
        print("Create the {} file and and populate it with your shodan.io API key".format(path_to_api))
    except Exception as e:
        print(e)
