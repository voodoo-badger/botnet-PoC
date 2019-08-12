# botnet-PoC

The goal is to automate the entire process of scanning a host, testing default credentials and if successful, add the address, username, and password to a list used for a simple ssh botnet.

The end result is intended for educational purposes only.

Ongoing:
- Writing the program that scans hosts for open port 22 and appends IP address to a file if port is open.
- Writing the program that dictionary attacks on known ssh servers.
- Writing the program that operates botnet/issues commands.

To Do:
- Solve transferring a Linux enumeration script to show potential ways of escalating privilege in instances where root user access has not yet been gained.
- Making the three programs function together in an automated fashion.
