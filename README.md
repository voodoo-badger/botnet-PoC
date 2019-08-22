# botnet-PoC

The goal is to automate the entire process of scanning a host, testing default credentials and if successful, add the address, username, and password to a list used for a simple ssh botnet. Two methods of scanning are present - Using shodan.io (Requires private API key) or a python script using the nmap module defaulting to scanning port 22 and 2222.
The end result is intended for educational purposes only.

Completed:
- Nmap scanner.
- Shodan.io ip and port gatherer.
- Dictionary attack on ssh service using pexpect.
- Command and Control central distributing commands to all known compromised hosts.

To Do:
- Streamline.
- Connect programs.
- Optimize and polish.
