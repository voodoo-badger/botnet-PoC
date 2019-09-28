# botnet-PoC

The goal is to automate the entire process of scanning a host, testing default credentials and if successful, add the address, username, and password to a list used for a simple ssh botnet. Two methods of scanning are present - Using shodan.io (Requires private API key) or a python script using the nmap module defaulting to scanning port 22 and 2222.
The end result is intended for educational purposes only.

How to use (Steps 1 and 2 are optional but recommended):

1. Create the virtual environment: ```python3 -m venv <path_to>/<virtual_environment>```
2. Activate the virtual environment: ```source <path-to>/<virtual_environment>/bin/activate```
3. Install requirements: ```pip install -r requirements.txt``` or ```pip3 install -r requirements.txt``` if there are different pip versions on your system.

```
Usage: initialize.py [-h] [-s SCAN] [-S] [-b] [-c] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -s SCAN, --scan SCAN  Scan for SSH servers locally. <-s> <IP-1>,<IP-2>
  -S, --shodan          Collect known SSH servers from Shodan.io
  -b, --brute           Perform dictionary attack on known hosts
  -c, --control         Use verified credentials and hosts to start the
                        Command and Control central
  -v, --verbose         Print results from selected actions
```
