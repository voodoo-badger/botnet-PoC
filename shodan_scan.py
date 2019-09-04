import shodan
import os
from termcolor import colored

"""
shodan_api_key.txt file added to .gitignore to avoid uploading private API key
"""

# Shodan API key here
path_to_api = "./shodan_api_key.txt"


def scan(api, verbose=False):
    api = shodan.Shodan(api)
    try:
        results = api.search("ssh")
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
            if verbose:
                # IP address and data
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
            SHODAN_API_KEY = key.readlines()
            scan(SHODAN_API_KEY, verbose)
    except Exception as e:
        print(e)
        print("Create the {} file and and populate it with your shodan.io API key".format(path_to_api))
