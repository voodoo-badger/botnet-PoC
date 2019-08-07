# botnet-PoC

The goal is to automate the entire process of scanning a host, testing default credentials and if successful, add the address, username, and password to a list used for a simple ssh botnet.

The end result is intended for educational purposes only.

Ongoing:
- Writing the program that scans hosts for open port 22 and appends IP address to a file if port is open.

To Do:
- Writing the program that performs dictionary attacks on the known targets and adds successful credentials to a file with the target IP addresses and their corresponding credentials.
- Writing the program that operates the botnet and transfers a Linux enumeration script to show potential ways of escalating privilege in instances where root user access has not yet been gained.
- Making the three programs function together in an automated fashion.

#DIBBLEDABBLE
