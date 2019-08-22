import shodan
import os
from termcolor import colored

# Shodan API key here
SHODAN_API_KEY = "YOUR_API_KEY"

api = shodan.Shodan(SHODAN_API_KEY)
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
